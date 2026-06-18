//! CLASSIFICATION: PUBLIC
//!
//! `ember orchestrator` — host-side entrypoint for the recursive SCION
//! topology (ADR 140 §3).
//!
//! `spawn` is the only place that can mint an orchestrator-class Persona.
//! In-container callers invoking `ember-scion start role=orchestrator` MUST
//! be refused at the broker boundary (privilege-escalation surface). The
//! flock guard at `/tmp/ember-orchestrator-<uid>.lock` closes MED-3 (two
//! simultaneous orchestrators cannot acquire the exclusive lock). The lock lives
//! in `/tmp` rather than `~/.ember/` so the operator uid can always create it
//! even after `~/.ember/` has been chowned to `ember:ember-clients` (ADR 131).

use std::ffi::CString;
use std::io::{BufRead, Write as IoWrite};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Subcommand;
use serde_json::{Value, json};
use tracing::debug;

use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::spawn::checkpoint::{SpawnCheckpoint, SpawnCheckpointResult, emit_checkpoint};
use ember_daemon::spawn::scion::mint_per_agent_proxy_ca;

/// Result of a successful `ember orchestrator spawn`.
///
/// `grant_id` is the attenuated child grant delegated onto the orchestrator
/// persona for this specific spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestratorSpawnResult {
    pub persona_id: String,
    pub grant_id: String,
    pub container_id: String,
    /// The daemon-minted ADR 154 bridge client bundle. `None`
    /// when the daemon could not mint it (e.g. bridge listener unconfigured) —
    /// the worker then starts without an emberd control plane (fail-soft,
    /// mirroring the daemon-sandbox lane).
    pub bridge_bundle: Option<OrchestratorBridgeBundle>,
}

/// The daemon-minted bridge client bundle returned by `create_agent_persona`.
/// The daemon owns the mint (it holds the bridge CA); the
/// orchestrator only materializes the returned PEMs into the container's
/// cert dir — it never mints locally.
#[derive(Clone, PartialEq, Eq)]
pub struct OrchestratorBridgeBundle {
    /// Port the daemon bridge listener is bound to; the container reaches it
    /// at `https://host.docker.internal:<port>`.
    pub port: u16,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_cert_pem: String,
}

// Manual Debug redacts `client_key_pem` (review MED-3) so the
// private key can never leak into a log line via a stray `{:?}` on the
// spawn result.
impl std::fmt::Debug for OrchestratorBridgeBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrchestratorBridgeBundle")
            .field("port", &self.port)
            .field("client_cert_pem", &self.client_cert_pem)
            .field("client_key_pem", &"<redacted>")
            .field("ca_cert_pem", &self.ca_cert_pem)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Clap enum
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum OrchestratorAction {
    /// Mint an orchestrator-class Persona and start the SCION topology.
    Spawn {
        /// Maximum recursion depth for SCION sub-orchestrators (1–8).
        #[arg(long, default_value_t = 2)]
        max_depth: u8,
        /// Construct template name used when spawning worker sandboxes.
        #[arg(long, default_value = "emberlink-worker")]
        template: String,
        /// Optional plain-text brief forwarded to the orchestrator process.
        #[arg(long)]
        brief: Option<String>,
        /// Optional spend-cap ceiling in USD (e.g. `0.10` → 10 cents) for the
        /// delegated grant minted on the orchestrator persona. When set the
        /// proxy preflight gate denies api.anthropic.com calls once cumulative
        /// metered cost on the grant exceeds this amount. Default: no cap.
        /// Drives Beat 5 ("Enforcement 1: spend cap") of the SCION demo.
        #[arg(long)]
        budget_usd: Option<String>,
        /// Extra host entries to inject into the container's /etc/hosts
        /// (passed as `extra_hosts:` in the inline SCION spawn config).
        /// Each entry must be in `hostname:ip` form (Docker compose syntax).
        /// Anchor: scion_extra_hosts_declarative.
        #[arg(long, value_name = "HOST:IP")]
        extra_hosts: Vec<String>,
    },
    /// Print the current orchestrator status.
    Status {
        /// Emit JSON output instead of human-readable text.
        #[arg(long)]
        verbose: bool,
        /// Stream new spawn checkpoints as they are written (Beat 3 demo flow).
        /// Implies --verbose. Polls the event log every 500ms until the
        /// terminating ContainerCreated or OrchestratorAgentReady checkpoint
        /// fires with a non-Ok result, OR until --follow-timeout-secs elapses.
        #[arg(long)]
        follow: bool,
        /// Maximum wall-clock seconds to stream checkpoints when --follow is
        /// set. Default 30s (matches the SCION demo's Beat 3 window).
        #[arg(long, default_value_t = 30)]
        follow_timeout_secs: u64,
    },
    /// Revoke the running orchestrator Persona and release the flock lock.
    Stop,
}

// ---------------------------------------------------------------------------
// Public command handlers
// ---------------------------------------------------------------------------

/// `ember orchestrator spawn` — validate args, acquire flock, mint an
/// orchestrator-class Persona via daemon RPC, then fork `ember-scion start`.
///
/// Exit semantics (returned as `Err(exit_code)`):
///   1 — invalid arguments or daemon error
///   2 — another orchestrator is already running (lock contended)
pub async fn cmd_orchestrator_spawn(
    cfg: &DaemonConfig,
    max_depth: u8,
    template: String,
    brief: Option<String>,
    budget_usd: Option<String>,
    extra_hosts: Vec<String>,
) -> Result<OrchestratorSpawnResult, i32> {
    // 1. Validate max_depth ∈ [1, 8].
    if max_depth == 0 || max_depth > 8 {
        eprintln!("ember orchestrator spawn: --max-depth must be in [1, 8], got {max_depth}");
        return Err(1);
    }

    // 1b. Parse --budget-usd to integer cents (None means "no spend cap").
    //     Drives Beat 5 of the SCION demo.
    let budget_cents: Option<u64> = match budget_usd.as_deref() {
        None => None,
        Some(s) => match parse_usd_to_cents(s) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("ember orchestrator spawn: --budget-usd: {e}");
                return Err(1);
            }
        },
    };

    // 2. Presence proof — broker host-socket enforcement is the dev0 guard.
    //    TODO: wire PAM/polkit (ADR 136 dev0)
    debug!("presence_proof stub — broker host-socket enforcement is the dev0 guard");

    // 3. Flock guard — acquire /tmp/ember-orchestrator-<uid>.lock exclusively
    //    and non-blocking. If the lock is contended, another orchestrator is
    //    already running.
    let lock_path = orchestrator_lock_path()?;
    // Ensure the parent directory exists.
    if let Some(parent) = lock_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            eprintln!("ember orchestrator spawn: create lock dir: {e}");
            1i32
        })?;
    }
    let _lock_guard = FlockGuard::acquire_nb(&lock_path).map_err(|e| match e {
        FlockError::Contended => {
            eprintln!(
                "ember orchestrator spawn: another orchestrator is already running; \
                 ember orchestrator status"
            );
            2i32
        }
        FlockError::Io(inner) => {
            eprintln!("ember orchestrator spawn: acquire lock: {inner}");
            1i32
        }
    })?;

    // 4. Mint orchestrator-class Persona via the daemon. Per ADR 140 §3 the
    //    operator persona issues a root grant; the orchestrator persona is
    //    delegated from that grant. Container UUID binds the daemon-side
    //    persona to the in-container per-agent UDS socket per ADR 140 §1.
    let socket_path = cfg.socket_dir.join("daemon.sock");

    // 4a. Fresh container UUID — also the SCION agent-name positional.
    let container_id = uuid::Uuid::new_v4().to_string();

    // 4b. Find or create the canonical operator persona (parent in
    //     delegation chain). Per ADR 140 §3 emberd owns this persona and
    //     uses it as the trust anchor for all orchestrator spawns.
    let operator_persona_id = daemon_find_operator_persona(&socket_path).map_err(|e| {
        eprintln!("ember orchestrator spawn: operator persona lookup failed: {e}");
        1i32
    })?;

    // 4c. Find or mint the operator's root grant. The mint path triggers
    //     operator-presence proof via the daemon's approval queue — the
    //     operator approves on the dashboard (storyboard Beat 2 by design).
    //     If a current root grant exists and is active, reuse it.
    let root_grant_id = daemon_find_or_mint_root_grant(&socket_path, &operator_persona_id)
        .map_err(|e| {
            eprintln!("ember orchestrator spawn: root grant lookup/mint failed: {e}");
            1i32
        })?;

    // 4d. Delegate from the root grant to a fresh orchestrator-class persona,
    //     bound to the container UUID. The child_scope is the maximal-permissive
    //     "*" under cohort A dev0 defaults; ADR 152's destination work narrows
    //     this to the per-method authority table.
    let spawn = daemon_create_agent_persona(
        &socket_path,
        &container_id,
        &root_grant_id,
        "*",
        max_depth,
        &template,
        budget_cents,
    )
    .map_err(|e| {
        eprintln!("ember orchestrator spawn: orchestrator persona delegation failed: {e}");
        1i32
    })?;
    let persona_id = spawn.persona_id.clone();

    println!(
        "orchestrator persona minted: {persona_id} (container={container_id}, parent_grant={root_grant_id})"
    );

    // Historical naming seam: `orchestrator_agent_ready` is emitted here so
    // `ember orchestrator status --verbose` can render live spawn progress,
    // but this happens before `ember-scion start` executes. Treat it as a
    // progress marker, not as a readiness proof. Failure is best-effort;
    // observability writes must not block the spawn flow.
    if let Err(e) = emit_checkpoint(
        &persona_id,
        SpawnCheckpoint::OrchestratorAgentReady {
            persona_id: persona_id.clone(),
        },
        SpawnCheckpointResult::Ok,
    )
    .await
    {
        debug!(error = %e, "emit OrchestratorAgentReady checkpoint failed");
    }

    // 4e. Mint per-agent CA and write it to the host-side path the SCION
    //     template bind-mounts at /run/ember-certs (entrypoint refuses to
    //     start without it). nameConstraints scope: api.anthropic.com,
    //     *.anthropic.com, github.com (defaults from mint_per_agent_proxy_ca).
    //     The CA key is not written to disk — only the cert is needed by
    //     the container's trust-store install step. Single-tenant fixed
    //     path for now; per-container_id scoping is tracked as follow-up
    //     work.
    // per_agent_ca_path_scoped_by_container_id
    let certs_dir = PathBuf::from(format!("/tmp/ember-agent-certs/{container_id}"));
    if let Err(e) = std::fs::create_dir_all(&certs_dir) {
        eprintln!("ember orchestrator spawn: create certs dir {certs_dir:?}: {e}");
        return Err(1);
    }
    let (ca_cert_pem, _ca_key_pem) =
        mint_per_agent_proxy_ca(&container_id, None, None).map_err(|e| {
            eprintln!("ember orchestrator spawn: mint per-agent CA: {e}");
            1i32
        })?;
    let ca_path = certs_dir.join("ca.pem");
    if let Err(e) = std::fs::write(&ca_path, ca_cert_pem.as_bytes()) {
        eprintln!("ember orchestrator spawn: write CA cert to {ca_path:?}: {e}");
        return Err(1);
    }
    // Make the cert world-readable so the agent uid inside the container
    // (mapped to whatever Docker chooses) can read it. The cert is public
    // by design — it's the trust anchor, not a secret.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o644)) {
            eprintln!("ember orchestrator spawn: chmod CA cert: {e}");
            return Err(1);
        }
    }
    debug!(path = %ca_path.display(), "per-agent CA cert written");

    // 4f-mtls. Materialize the daemon-minted bridge client bundle.
    //     The daemon minted it as part of `create_agent_persona` — the
    //     spawn-mint owns the cert (it holds the ADR 154 bridge CA; ADR 209
    //     §2/§5), so the orchestrator only writes the returned PEMs, never mints
    //     locally. `EMBER_DAEMON_ENDPOINT` is wired from the bundle port so the
    //     in-container agent reaches emberd's bridge listener over mTLS.
    // orchestrator_spawn_materializes_daemon_minted_bridge_client_bundle
    let cert_dir = PathBuf::from("/tmp/ember-agent-certs"); // per-container subdirs created inside
    let mut daemon_endpoint: Option<String> = std::env::var("EMBER_DAEMON_ENDPOINT").ok();
    match spawn.bridge_bundle.as_ref() {
        Some(bundle) => {
            materialize_bridge_client_cert_for_container(
                &container_id,
                &cert_dir,
                &bundle.client_cert_pem,
                &bundle.client_key_pem,
                &bundle.ca_cert_pem,
            )
            .map_err(|e| {
                eprintln!("ember orchestrator spawn: materialize bridge client cert: {e}");
                1i32
            })?;
            // The daemon bridge listens on the host; the container reaches it at
            // host.docker.internal:<port> (ADR 154). An ambient
            // EMBER_DAEMON_ENDPOINT override, if present, wins.
            daemon_endpoint
                .get_or_insert_with(|| format!("https://host.docker.internal:{}", bundle.port));
            debug!(
                port = bundle.port,
                "materialized daemon-minted bridge client bundle; EMBER_DAEMON_ENDPOINT wired"
            );
        }
        None => {
            // FAIL CLOSED (review HIGH-3). The bundle is the
            // worker's mTLS identity; unlike the daemon-sandbox lane, the SCION
            // lane has no session-runtime authority anchor to fall back on, so
            // a missing bundle must NOT silently downgrade the worker to a
            // no-control-plane start. Refuse the spawn with an actionable error
            // (the daemon bridge listener is almost certainly unconfigured).
            eprintln!(
                "ember orchestrator spawn: refusing to spawn — the daemon returned no bridge \
                 client bundle, so the worker would have no mTLS identity / emberd control plane. \
                 Ensure the daemon bridge listener is configured ([daemon].bridge_bind) and the \
                 vault is unlocked, then retry."
            );
            return Err(1);
        }
    }

    // 5. Invoke `ember-scion start` via the Construct shim with emberlink-
    //    shaped argv. The shim's argv-translation layer (scion.rs::translate_
    //    scion_argv) strips --persona / --max-depth / --brief and renames
    //    --template → --type before exec'ing the upstream scion binary, so
    //    scion sees only its own native vocabulary. Per ADR 140 §4 the shim
    //    is also the broker.resolve gate for spawn-subagent authority
    //    (capability check, scope attenuation, template-allowlist, depth cap).
    // 4f. Write a per-spawn SCION inline config carrying EMBER_PERSONA_ID
    //     and EMBER_DAEMON_SOCKET into the container's env. The base image
    //     (ember-claude-code:v1) requires EMBER_PERSONA_ID at startup for
    //     MCP-config substitution; without it the entrypoint refuses to
    //     start. The inline config merges with the named template via
    //     scion's --config path (see scion/cmd/common.go::RunAgent).
    let socket_path_str = socket_path.to_str().ok_or_else(|| {
        eprintln!("ember orchestrator spawn: non-utf8 socket path: {socket_path:?}");
        1i32
    })?;
    // In-container daemon socket path. SCION template bind-mounts the host
    // socket (socket_path_str) → this path inside the container.
    // The uid bridge work is tracked as follow-up
    // (Docker Desktop on macOS does not pass through Linux UDS peer-cred
    // identically; first connect will likely surface the bridge gap).
    let in_container_socket = "/run/ember/daemon.sock";

    // `daemon_endpoint` was resolved above (4f-mtls): the daemon-minted
    // bundle's bridge port, or an ambient EMBER_DAEMON_ENDPOINT override.
    // Injected into the container env below so the agent reaches emberd over
    // the mTLS bridge. Anchor: scion_extra_hosts_declarative.

    // Build the env block for the inline SCION config.
    let mut env_block = format!(
        "  EMBER_PERSONA_ID: {persona_id}\n  EMBER_DAEMON_SOCKET: {in_container_socket}\n  EMBER_ORCHESTRATOR_CONTAINER_ID: {container_id}\n  EMBER_ORCHESTRATOR_PARENT_GRANT_ID: {root_grant_id}\n"
    );
    if let Some(ref endpoint) = daemon_endpoint {
        env_block.push_str(&format!("  EMBER_DAEMON_ENDPOINT: {endpoint}\n"));
        debug!(endpoint = %endpoint, "EMBER_DAEMON_ENDPOINT probed and wired into inline scion config");
    }

    // Build the extra_hosts block for the inline SCION config.
    // Each entry in extra_hosts is passed as-is (Docker compose hostname:ip syntax).
    let extra_hosts_block = if extra_hosts.is_empty() {
        String::new()
    } else {
        let mut block = "extra_hosts:\n".to_string();
        for entry in &extra_hosts {
            block.push_str(&format!("  - \"{entry}\"\n"));
        }
        block
    };

    let inline_cfg_yaml = format!(
        "schema_version: \"1\"\nenv:\n{env_block}volumes:\n  - source: {socket_path_str}\n    target: {in_container_socket}\n    read_only: false\n{extra_hosts_block}"
    );
    let inline_cfg_path = std::env::temp_dir().join(format!("ember-spawn-{container_id}.yaml"));
    if let Err(e) = std::fs::write(&inline_cfg_path, inline_cfg_yaml.as_bytes()) {
        eprintln!("ember orchestrator spawn: write inline scion config: {e}");
        return Err(1);
    }
    debug!(path = %inline_cfg_path.display(), "wrote per-spawn scion config");

    // Invoke ember-scion with emberlink-shaped argv. The Construct shim
    // translates these to scion-native argv before exec'ing the upstream
    // scion binary (ADR 140 §4 step 3). The --persona / --max-depth / --brief
    // flags are stripped by translate_scion_argv; --template is renamed to
    // --type; --non-interactive is injected automatically for "start".
    let ember_scion_bin = env_or_path_scion();
    let mut cmd = std::process::Command::new(&ember_scion_bin);
    cmd.arg("start");
    cmd.arg(&container_id);
    cmd.arg("--persona").arg(&persona_id);
    cmd.arg("--max-depth").arg(max_depth.to_string());
    cmd.arg("--template").arg(&template);
    cmd.arg("--config").arg(&inline_cfg_path);
    if let Some(ref b) = brief {
        cmd.arg("--brief").arg(b);
    }
    cmd.env("EMBER_ORCHESTRATOR_PERSONA", &persona_id)
        .env("EMBER_ORCHESTRATOR_CONTAINER_ID", &container_id)
        .env("EMBER_ORCHESTRATOR_PARENT_GRANT_ID", &root_grant_id)
        .env("EMBER_SCION_MAX_DEPTH", max_depth.to_string());

    debug!(binary = %ember_scion_bin, persona = %persona_id, "launching ember-scion start via Construct shim");

    // Emit DockerRunRequested before invoking scion — the next checkpoint
    // (ContainerCreated) fires only on success of the scion start.
    if let Err(e) = emit_checkpoint(
        &persona_id,
        SpawnCheckpoint::DockerRunRequested,
        SpawnCheckpointResult::Ok,
    )
    .await
    {
        debug!(error = %e, "emit DockerRunRequested checkpoint failed");
    }

    match cmd.status() {
        Ok(status) if status.success() => {
            println!("ember-scion exited successfully");
            if let Err(e) = emit_checkpoint(
                &persona_id,
                SpawnCheckpoint::ContainerCreated {
                    container_id: container_id.clone(),
                },
                SpawnCheckpointResult::Ok,
            )
            .await
            {
                debug!(error = %e, "emit ContainerCreated checkpoint failed");
            }
            Ok(spawn)
        }
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            eprintln!("ember-scion exited with status {code}");
            let _ = emit_checkpoint(
                &persona_id,
                SpawnCheckpoint::ContainerCreated {
                    container_id: container_id.clone(),
                },
                SpawnCheckpointResult::Err {
                    reason: format!("scion start exited {code}"),
                },
            )
            .await;
            Err(1)
        }
        Err(e) => {
            eprintln!("ember orchestrator spawn: failed to launch {ember_scion_bin}: {e}");
            Err(1)
        }
    }
    // _lock_guard drops here → flock released automatically on process exit.
}

/// `ember orchestrator status` — read flock state and query daemon.
pub async fn cmd_orchestrator_status(
    cfg: &DaemonConfig,
    verbose: bool,
    follow: bool,
    follow_timeout_secs: u64,
) -> Result<(), i32> {
    let lock_path = orchestrator_lock_path().map_err(|_| 1i32)?;
    let running = is_lock_held(&lock_path);
    let socket_path = cfg.socket_dir.join("daemon.sock");

    // Query daemon for orchestrator persona if running.
    // When --follow is set but no orchestrator is currently running (cmd
    // exits as soon as `scion start` returns; flock releases), fall back
    // to the most recent `orchestrator_agent_ready` checkpoint in the
    // event log so the operator can pipe `spawn` → `status --follow` in
    // two panes per the SCION Beat 3 flow.
    let mut persona_id = if running {
        daemon_query_orchestrator_persona(&socket_path).unwrap_or_else(|_| "<unknown>".to_string())
    } else {
        String::new()
    };
    if follow && (persona_id.is_empty() || persona_id == "<unknown>") {
        let events = tail_engine_events_silent(1000);
        for v in events.iter().rev() {
            let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
            let event = v.get("event").and_then(Value::as_str).unwrap_or("");
            if event == "spawn_checkpoint"
                && kind == "orchestrator_agent_ready"
                && let Some(pid) = v.get("agent_id").and_then(Value::as_str)
            {
                persona_id = pid.to_string();
                break;
            }
        }
    }

    if verbose || follow {
        let started_at = if running {
            lock_mtime(&lock_path)
                .map(format_system_time)
                .unwrap_or_else(|| "<unknown>".to_string())
        } else {
            String::new()
        };
        let out = json!({
            "running": running,
            "persona_id": if running { persona_id.as_str() } else { "" },
            "started_at": started_at,
            "max_depth": null,
            "template": null,
            "child_count": null,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());

        // Tail the daemon event log for spawn checkpoint entries.
        // The agent_id used as the filter key is the orchestrator persona_id.
        if !persona_id.is_empty() && persona_id != "<unknown>" {
            if follow {
                stream_spawn_checkpoints(&persona_id, follow_timeout_secs).await;
            } else {
                print_spawn_checkpoints(&persona_id);
            }
        }
    } else if running {
        println!("orchestrator: running (persona: {persona_id})");
    } else {
        println!("orchestrator: not running");
    }
    Ok(())
}

/// `ember orchestrator stop` — revoke the orchestrator Persona via daemon RPC
/// and release the flock.
pub async fn cmd_orchestrator_stop(cfg: &DaemonConfig) -> Result<(), i32> {
    let lock_path = orchestrator_lock_path().map_err(|_| 1i32)?;
    if !is_lock_held(&lock_path) {
        eprintln!("ember orchestrator stop: no orchestrator is running");
        return Err(1);
    }

    let socket_path = cfg.socket_dir.join("daemon.sock");
    // Revoke persona — best-effort; log on error but continue to remove lock.
    let persona_id =
        daemon_query_orchestrator_persona(&socket_path).unwrap_or_else(|_| "<unknown>".to_string());

    if let Err(e) = daemon_revoke_persona(&socket_path, &persona_id) {
        eprintln!("ember orchestrator stop: revoke RPC warning: {e}");
    }

    // Remove the lock file so a fresh orchestrator can start.
    if let Err(e) = std::fs::remove_file(&lock_path) {
        eprintln!("ember orchestrator stop: remove lock file: {e}");
    }

    println!("orchestrator stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Bridge client cert materialization
// ---------------------------------------------------------------------------

/// Paths to the materialized per-agent mTLS client cert files.
///
/// Returned by `materialize_bridge_client_cert_for_container`. The PEMs are
/// minted daemon-side and written verbatim by the orchestrator.
/// Anchor: orchestrator_spawn_materializes_daemon_minted_bridge_client_bundle
#[derive(Debug)]
pub struct MaterializedCert {
    /// Path to the DER/PEM client certificate (`client.crt`, mode 0644).
    pub cert_path: PathBuf,
    /// Path to the private key (`client.key`, mode 0600).
    pub key_path: PathBuf,
    /// Path to the CA certificate that signed the client cert (`client-ca.crt`, mode 0644).
    pub ca_path: PathBuf,
}

/// Errors from `materialize_bridge_client_cert_for_container`.
#[derive(Debug, thiserror::Error)]
pub enum BridgeCertError {
    #[error("failed to create per-container cert directory {path}: {source}")]
    CreateDirFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write client cert to {path}: {source}")]
    WriteCertFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write client key to {path}: {source}")]
    WriteKeyFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write CA cert to {path}: {source}")]
    WriteCaFailed {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Create `<output_dir>/<container_id>/` (mode 0700) and write the
/// daemon-minted bridge client bundle into it, returning the paths as a
/// [`MaterializedCert`].
///
/// File layout:
/// - `client.crt`    (mode 0644) — the daemon-minted client certificate
/// - `client.key`    (mode 0600) — the client private key
/// - `client-ca.crt` (mode 0644) — the bridge CA trust root
///
/// The PEMs are minted **daemon-side** (the daemon holds the
/// ADR 154 bridge CA, mlock'd, never on disk) and returned by
/// `create_agent_persona`; the orchestrator only writes them. The SPIFFE SAN
/// (`spiffe://emberd/persona/<id>` + `spiffe://emberd/container/<id>`) is the
/// container's mTLS identity per ADR 209 §2. The directory is scoped per
/// container so concurrent spawns don't collide.
fn materialize_bridge_client_cert_for_container(
    container_id: &str,
    output_dir: &Path,
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_cert_pem: &str,
) -> Result<MaterializedCert, BridgeCertError> {
    use std::os::unix::fs::PermissionsExt;

    let container_dir = output_dir.join(container_id);
    // Create the cert dirs with 0700 from the start (atomic perms, not
    // default-then-chmod) so the private key written below is never even
    // momentarily traversable by another uid (review MED-2). On
    // unix the 0700 mode is applied to every dir created in the chain,
    // including the `/tmp/ember-agent-certs` root, and a failure is fatal —
    // we will not write a private key into a dir we couldn't lock down.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&container_dir)
            .map_err(|e| BridgeCertError::CreateDirFailed {
                path: container_dir.clone(),
                source: e,
            })?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&container_dir).map_err(|e| BridgeCertError::CreateDirFailed {
        path: container_dir.clone(),
        source: e,
    })?;

    let cert_path = container_dir.join("client.crt");
    let key_path = container_dir.join("client.key");
    let ca_path = container_dir.join("client-ca.crt");

    // Write the daemon-minted client.crt (mode 0644).
    std::fs::write(&cert_path, client_cert_pem.as_bytes()).map_err(|e| {
        BridgeCertError::WriteCertFailed {
            path: cert_path.clone(),
            source: e,
        }
    })?;
    #[cfg(unix)]
    {
        let _ = std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644));
    }

    // Write the client.key (mode 0600 — private key).
    std::fs::write(&key_path, client_key_pem.as_bytes()).map_err(|e| {
        BridgeCertError::WriteKeyFailed {
            path: key_path.clone(),
            source: e,
        }
    })?;
    #[cfg(unix)]
    {
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    // Write the bridge CA trust root client-ca.crt (mode 0644).
    std::fs::write(&ca_path, ca_cert_pem.as_bytes()).map_err(|e| {
        BridgeCertError::WriteCaFailed {
            path: ca_path.clone(),
            source: e,
        }
    })?;
    #[cfg(unix)]
    {
        let _ = std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o644));
    }

    debug!(
        container_id = %container_id,
        cert = %cert_path.display(),
        key = %key_path.display(),
        ca = %ca_path.display(),
        "materialized bridge client cert stubs"
    );

    Ok(MaterializedCert {
        cert_path,
        key_path,
        ca_path,
    })
}

/// Resolve the canonical orchestrator lock path.
///
/// Under ADR 131 (separate-uid daemon), `~/.ember/` is chowned to
/// `ember:ember-clients` during install. The orchestrator lock is created
/// by the CLI running as the operator uid, not by the daemon. Placing it
/// inside `~/.ember/` would cause EACCES on the `O_CREAT|O_WRONLY` open
/// after install completes.
///
/// Instead the lock lives in `/tmp` keyed to the invoking uid so:
///   - the operator uid can always create and hold it;
///   - two operators on the same machine (multi-user host) get independent
///     lock files (each uid has its own slot);
///   - the path is stable across reboots within a session (uid does not
///     change) but is cleaned on OS restart (tmp-sweep).
///
/// Lock filename: `/tmp/ember-orchestrator-<uid>.lock`
fn orchestrator_lock_path() -> Result<PathBuf, i32> {
    // SAFETY: getuid(2) is always safe and never fails.
    let uid = unsafe { libc::getuid() };
    Ok(PathBuf::from(format!("/tmp/ember-orchestrator-{uid}.lock")))
}

/// Return `$EMBER_SCION_BIN` if set, otherwise `"ember-scion"` (resolved via
/// `$PATH`). Never touches the shell — uses `std::env::var` only.
fn env_or_path_scion() -> String {
    std::env::var("EMBER_SCION_BIN").unwrap_or_else(|_| "ember-scion".to_string())
}

/// Check whether the orchestrator lock file is held by another process.
/// Returns `true` if the file exists *and* a non-blocking exclusive flock
/// attempt fails (EWOULDBLOCK), meaning another holder is active.
fn is_lock_held(lock_path: &Path) -> bool {
    if !lock_path.exists() {
        return false;
    }
    // Try to acquire non-blocking; if it fails the lock is held.
    match FlockGuard::acquire_nb(lock_path) {
        Ok(_guard) => false, // we got it — nobody else holds it
        Err(FlockError::Contended) => true,
        Err(_) => false,
    }
}

/// Read the mtime of the lock file (used for `started_at` approximation).
fn lock_mtime(lock_path: &Path) -> Option<SystemTime> {
    std::fs::metadata(lock_path)
        .ok()
        .and_then(|m| m.modified().ok())
}

/// Format a `SystemTime` as an RFC-3339-like UTC string.
/// Parse a USD dollar string (e.g. `"0.10"`, `"1.50"`, `"42"`) into an
/// integer-cents budget. Used by `ember orchestrator spawn --budget-usd`
/// to populate the delegated grant's `Statement.budget.cents` ceiling
/// (Beat 5 of the SCION demo). Rejects negative input.
fn parse_usd_to_cents(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.starts_with('-') {
        return Err("negative budget not allowed".to_string());
    }
    let val: f64 = trimmed
        .parse()
        .map_err(|_| format!("invalid decimal value '{s}'"))?;
    if val < 0.0 {
        return Err("negative budget not allowed".to_string());
    }
    Ok((val * 100.0).round() as u64)
}

fn format_system_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal formatting: epoch seconds. Full ISO-8601 needs a time crate
    // dependency not in scope for this slice.
    format!("{secs}")
}

// ---------------------------------------------------------------------------
// Flock guard
// ---------------------------------------------------------------------------

/// Errors from [`FlockGuard`].
#[derive(Debug)]
enum FlockError {
    /// Another process already holds the lock (`EWOULDBLOCK`).
    Contended,
    /// An unexpected I/O error occurred.
    Io(std::io::Error),
}

/// RAII guard that holds an exclusive `flock(2)` on a file descriptor.
/// The fd is closed (and the lock released) when the guard drops.
#[derive(Debug)]
struct FlockGuard {
    fd: RawFd,
}

impl FlockGuard {
    /// Open (or create) `path` and acquire an exclusive non-blocking flock.
    /// Returns `Err(FlockError::Contended)` if another process holds the lock.
    fn acquire_nb(path: &Path) -> Result<Self, FlockError> {
        let c_path = CString::new(path.to_str().ok_or_else(|| {
            FlockError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        })?)
        .map_err(|_| FlockError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;

        // SAFETY: open(2) is a standard POSIX syscall. O_CREAT | O_WRONLY
        // creates the file if it does not exist, mode 0600.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                0o600i32,
            )
        };
        if fd < 0 {
            return Err(FlockError::Io(std::io::Error::last_os_error()));
        }

        // SAFETY: flock(2) operates on the fd we just opened. LOCK_EX |
        // LOCK_NB returns EWOULDBLOCK if the lock is already held.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: closing our own fd is always safe.
            unsafe { libc::close(fd) };
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(FlockError::Contended);
            }
            return Err(FlockError::Io(err));
        }

        Ok(Self { fd })
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: close(2) on our own fd is always safe. The kernel
        // releases the associated flock when the last fd referencing the
        // open-file description closes.
        unsafe { libc::close(self.fd) };
    }
}

// ---------------------------------------------------------------------------
// Daemon socket helpers
// ---------------------------------------------------------------------------

/// Errors from daemon socket calls in this module.
#[derive(Debug)]
enum OrchestratorRpcError {
    DaemonUnavailable {
        socket: PathBuf,
        source: std::io::Error,
    },
    Guidance(String),
    Io(String),
    Protocol(String),
    DaemonRpc {
        code: i32,
        message: String,
    },
    /// Operator denied the approval request on the dashboard.
    ApprovalDenied {
        approval_id: String,
        reason: String,
    },
    /// Approval request was not resolved before the polling deadline.
    ApprovalTimedOut {
        approval_id: String,
        timeout_secs: u64,
    },
}

impl std::fmt::Display for OrchestratorRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonUnavailable { socket, source } => {
                write!(f, "{}", crate::format_daemon_unavailable(socket, source))
            }
            Self::Guidance(s) => write!(f, "{s}"),
            Self::Io(s) => write!(f, "socket I/O: {s}"),
            Self::Protocol(s) => write!(f, "protocol: {s}"),
            Self::DaemonRpc { code, message } => write!(f, "daemon error ({code}): {message}"),
            Self::ApprovalDenied {
                approval_id,
                reason,
            } => write!(
                f,
                "approval {approval_id} denied: {reason} — review at http://localhost:3141/approvals"
            ),
            Self::ApprovalTimedOut {
                approval_id,
                timeout_secs,
            } => write!(
                f,
                "approval {approval_id} timed out after {timeout_secs}s — resolve at http://localhost:3141/approvals"
            ),
        }
    }
}

fn orchestrator_guidance_for_rpc(code: i32, message: &str) -> Option<String> {
    if code == -32001 && message.contains("authority_class_not_met") {
        return Some(
            "this orchestrator action needs operator presence on the daemon-managed vault lane. \
             Re-run it from an interactive operator shell and use the managed separate-uid \
             biometric unlock flow when available, or restart the daemon with \
             `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe bootstrap."
                .to_string(),
        );
    }

    if code == -32030
        && (message.contains("session is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked"))
    {
        return Some(
            "this orchestrator action needs operator presence on the daemon-managed vault lane. \
             Use the managed separate-uid biometric unlock flow when available, or restart the \
             daemon with `EMBER_VAULT_PASSPHRASE` for a fresh dev-probe bootstrap; same-daemon \
             operator-uid reopen is intentionally disabled."
                .to_string(),
        );
    }

    None
}

/// Send a synchronous JSON-RPC request over the daemon Unix socket and
/// return the `result` value.
fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, OrchestratorRpcError> {
    match crate::call_daemon_rpc(socket_path, method, params) {
        Ok(result) => Ok(result),
        Err(crate::DaemonRpcError::Unavailable(source)) => {
            Err(OrchestratorRpcError::DaemonUnavailable {
                socket: socket_path.to_path_buf(),
                source,
            })
        }
        Err(crate::DaemonRpcError::PermissionDenied(e)) => Err(OrchestratorRpcError::Io(
            crate::format_daemon_socket_io_error(&e),
        )),
        Err(crate::DaemonRpcError::Io(e)) => Err(OrchestratorRpcError::Io(format!("{e}"))),
        Err(crate::DaemonRpcError::Protocol(e)) => Err(OrchestratorRpcError::Protocol(e)),
        Err(crate::DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = orchestrator_guidance_for_rpc(code, &message) {
                return Err(OrchestratorRpcError::Guidance(guidance));
            }
            Err(OrchestratorRpcError::DaemonRpc { code, message })
        }
    }
}

/// Resolve the operator's persona — the trust anchor whose enrolled passkey
/// gates the root-grant mint. Per ADR 140 §3 the orchestrator's root grant
/// is delegated from the human operator's persona, not from a synthetic
/// daemon-managed identity.
///
/// Resolution order (first match wins):
///   1. `EMBER_OPERATOR_PERSONA_NAME` env override (escape hatch for test /
///      multi-operator setups).
///   2. `$USER` — direct match (e.g. operator with persona named "operator").
///   3. `$USER-dev` — install-default shape (e.g. "operator-dev", the persona
///      `ember daemon install` creates and enrolls passkeys against).
///   4. `operator` — explicit canonical name (some installs use this).
///   5. Any persona with `status == "active"` — last-resort fallback.
///
/// Returns the persona_id. No new persona is created: if none of the above
/// match the operator should run `ember persona create` + `/settings/passkeys`
/// before retrying — that flow has the right UX for first-run.
fn daemon_find_operator_persona(socket_path: &Path) -> Result<String, OrchestratorRpcError> {
    let listed = call_daemon(socket_path, "list_personas", &json!({}))?;
    let arr = listed.as_array().ok_or_else(|| {
        OrchestratorRpcError::Protocol("list_personas: expected array".to_string())
    })?;

    let user = std::env::var("USER").unwrap_or_default();
    let override_name = std::env::var("EMBER_OPERATOR_PERSONA_NAME").ok();
    let candidates: Vec<String> = {
        let mut v = Vec::new();
        if let Some(name) = override_name {
            v.push(name);
        }
        if !user.is_empty() {
            v.push(user.clone());
            v.push(format!("{user}-dev"));
        }
        v.push("operator".to_string());
        v
    };

    for candidate in &candidates {
        for p in arr {
            if p.get("name").and_then(|v| v.as_str()) == Some(candidate.as_str())
                && let Some(id) = p.get("id").and_then(|v| v.as_str())
            {
                return Ok(id.to_string());
            }
        }
    }

    // Last-resort fallback: any active persona. Better to delegate from
    // something than to refuse outright; the operator can override via env
    // if the picked persona is wrong.
    for p in arr {
        let status = p.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status == "active"
            && let Some(id) = p.get("id").and_then(|v| v.as_str())
        {
            return Ok(id.to_string());
        }
    }

    Err(OrchestratorRpcError::Protocol(format!(
        "no operator persona found; tried names: {candidates:?}. Run `ember persona create --name $USER-dev` and enroll a passkey via the dashboard first."
    )))
}

/// Find an active `_orchestrator_root` grant for the operator persona, or
/// mint one. Per ADR 140 §3 the root grant is held under operator-presence
/// proof — the mint call triggers the daemon's approval queue and a
/// dashboard notification. The operator approves on the dashboard
/// (storyboard Beat 2).
///
/// The grant uses a synthetic `credential_name` (`_orchestrator_root`)
/// because `create_grant` is credential-shaped today; the destination work
/// replaces this with a proper delegation primitive that doesn't
/// piggyback on credential_name.
///
/// When `create_grant` returns `{status:"pending_approval", approval_id}`,
/// this function blocks on the daemon's `await_approval` RPC (up to
/// `APPROVAL_TIMEOUT_SECS`) and, on success, calls `list_grants` to
/// resolve the newly-minted grant ID.
fn daemon_find_or_mint_root_grant(
    socket_path: &Path,
    persona_id: &str,
) -> Result<String, OrchestratorRpcError> {
    let listed = call_daemon(
        socket_path,
        "list_grants",
        &json!({ "persona_id": persona_id }),
    )?;
    let arr = listed
        .as_array()
        .ok_or_else(|| OrchestratorRpcError::Protocol("list_grants: expected array".to_string()))?;
    for g in arr {
        let credential = g
            .get("credential_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = g.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if credential == "_orchestrator_root"
            && status == "active"
            && let Some(id) = g.get("id").and_then(|v| v.as_str())
        {
            return Ok(id.to_string());
        }
    }
    eprintln!(
        "ember orchestrator spawn: minting root grant for operator (approve on dashboard at http://localhost:3141 if prompted)"
    );
    // max_delegation_depth must be set on the root grant or the daemon's
    // delegate_grant call rejects with "parent does not allow delegation"
    // when the orchestrator persona tries to inherit. 8 matches the
    // orchestrator's --max-depth ceiling (see arg validation at the top of
    // cmd_orchestrator_spawn) so every legal --max-depth value can be
    // satisfied by this single root grant.
    let created = call_daemon(
        socket_path,
        "create_grant",
        &json!({
            "persona_id": persona_id,
            "credential_name": "_orchestrator_root",
            "scope": "*",
            "max_delegation_depth": 8,
        }),
    )?;

    // Handle pending_approval: daemon requires operator sign-off before the
    // grant is minted. Block on `await_approval` then re-query list_grants
    // to obtain the result_grant_id once the approval resolves.
    if created.get("status").and_then(|v| v.as_str()) == Some("pending_approval") {
        let approval_id = created
            .get("approval_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OrchestratorRpcError::Protocol(
                    "pending_approval response missing approval_id field".to_string(),
                )
            })?
            .to_string();
        eprintln!(
            "ember orchestrator spawn: waiting on dashboard approval (approval_id={approval_id}) — visit http://localhost:3141/approvals"
        );
        daemon_await_grant_approval(socket_path, persona_id, &approval_id)?;
        // Approval succeeded; the daemon has now minted the grant.
        // Re-query list_grants to retrieve the result_grant_id.
        return daemon_find_active_root_grant(socket_path, persona_id, &approval_id);
    }

    created
        .get("grant_id")
        .or_else(|| created.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            OrchestratorRpcError::Protocol(
                "create_grant response missing grant_id/id field".to_string(),
            )
        })
}

/// Block on the daemon's `await_approval` RPC until the operator resolves
/// the approval request identified by `approval_id`. Returns `Ok(())` on
/// approval, or a descriptive `Err` on denial or timeout.
///
/// The read deadline on the socket is set to `APPROVAL_TIMEOUT_SECS + 5s`
/// so we always outlast the daemon's own polling deadline.
fn daemon_await_grant_approval(
    socket_path: &Path,
    _persona_id: &str,
    approval_id: &str,
) -> Result<(), OrchestratorRpcError> {
    // Five minutes — matches the proxy hook's default.
    const APPROVAL_TIMEOUT_SECS: u64 = 300;

    // Open a new socket connection with an extended read deadline so the
    // blocking `await_approval` poll can run to completion.
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        OrchestratorRpcError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;
    // Read budget = daemon's poll deadline + 5 s slack so our socket does not
    // time out before the daemon's own `TimedOut` response can land.
    let read_deadline = std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS.saturating_add(5));
    stream
        .set_read_timeout(Some(read_deadline))
        .map_err(|e| OrchestratorRpcError::Io(format!("set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| OrchestratorRpcError::Io(format!("set write timeout: {e}")))?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| OrchestratorRpcError::Io(format!("clone socket: {e}")))?;
    let mut reader = std::io::BufReader::new(stream);

    let request = json!({
        "id": "orchestrator-await-approval",
        "method": "await_approval",
        "params": {
            "request_id": approval_id,
            "timeout_secs": APPROVAL_TIMEOUT_SECS,
        },
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| OrchestratorRpcError::Io(format!("write await_approval request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| OrchestratorRpcError::Io(format!("read await_approval response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim()).map_err(|e| {
        OrchestratorRpcError::Protocol(format!(
            "invalid JSON-RPC response from await_approval: {e}"
        ))
    })?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(OrchestratorRpcError::DaemonRpc { code, message });
    }

    let result = response.get("result").cloned().unwrap_or(Value::Null);
    let kind = result
        .get("decision")
        .and_then(|d| d.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("unknown");

    match kind {
        "approved" => Ok(()),
        "denied" => {
            let reason = result
                .get("decision")
                .and_then(|d| d.get("reason"))
                .and_then(|r| r.as_str())
                .unwrap_or("no reason provided")
                .to_string();
            Err(OrchestratorRpcError::ApprovalDenied {
                approval_id: approval_id.to_string(),
                reason,
            })
        }
        "timed_out" => Err(OrchestratorRpcError::ApprovalTimedOut {
            approval_id: approval_id.to_string(),
            timeout_secs: APPROVAL_TIMEOUT_SECS,
        }),
        other => Err(OrchestratorRpcError::Protocol(format!(
            "await_approval returned unexpected decision kind: {other}"
        ))),
    }
}

/// Re-query `list_grants` to find the active `_orchestrator_root` grant
/// that the daemon created after the approval resolved. Called after
/// `daemon_await_grant_approval` returns `Ok(())`.
fn daemon_find_active_root_grant(
    socket_path: &Path,
    persona_id: &str,
    approval_id: &str,
) -> Result<String, OrchestratorRpcError> {
    let listed = call_daemon(
        socket_path,
        "list_grants",
        &json!({ "persona_id": persona_id }),
    )?;
    let arr = listed.as_array().ok_or_else(|| {
        OrchestratorRpcError::Protocol("list_grants (post-approval): expected array".to_string())
    })?;
    for g in arr {
        let credential = g
            .get("credential_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = g.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if credential == "_orchestrator_root"
            && status == "active"
            && let Some(id) = g.get("id").and_then(|v| v.as_str())
        {
            return Ok(id.to_string());
        }
    }
    Err(OrchestratorRpcError::Protocol(format!(
        "no active _orchestrator_root grant found after approval {approval_id} resolved; \
         the daemon may not have minted the grant yet — retry spawn or check the dashboard"
    )))
}

/// Mint the orchestrator-class Persona via `create_agent_persona` daemon RPC.
/// Returns the minted `persona_id`. Per ADR 140 §1 + §3: persona is bound to
/// `container_id` and delegated from `parent_grant_id`; `child_scope` is the
/// scope the orchestrator inherits from the root grant.
fn daemon_create_agent_persona(
    socket_path: &Path,
    container_id: &str,
    parent_grant_id: &str,
    child_scope: &str,
    max_depth: u8,
    template: &str,
    budget_cents: Option<u64>,
) -> Result<OrchestratorSpawnResult, OrchestratorRpcError> {
    // Use a per-spawn persona name so re-spawns under the same operator do
    // not collide. The short prefix of container_id keeps the name readable
    // in dashboards + audit logs.
    let short = &container_id[..container_id.len().min(8)];
    let mut params = json!({
        "name": format!("orchestrator-{short}"),
        "container_id": container_id,
        "parent_grant_id": parent_grant_id,
        "child_scope": child_scope,
        "spawn_subagent": {
            "max_depth": max_depth,
            "allowed_templates": [template],
        },
        // Request the daemon-minted ADR 154 bridge client bundle
        // as part of the same daemon-owned spawn-mint. The daemon holds the
        // bridge CA; the orchestrator never mints the cert locally.
        "bridge_client_bundle": true,
    });
    if let Some(cents) = budget_cents {
        // The daemon's create_agent_persona RPC accepts a `budget` field
        // (handler.rs:4885) that deserializes into core_grant_types::Budget. Map
        // to the canonical shape {cents: <N>} so the delegated grant's
        // statement carries the spend cap.
        params["budget"] = json!({ "cents": cents });
    }
    let result = call_daemon(socket_path, "create_agent_persona", &params)?;
    let persona_id = result
        .get("persona_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OrchestratorRpcError::Protocol(
                "create_agent_persona response missing persona_id".to_string(),
            )
        })?
        .to_string();
    let grant_id = result
        .get("attenuated_grant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OrchestratorRpcError::Protocol(
                "create_agent_persona response missing attenuated_grant_id".to_string(),
            )
        })?
        .to_string();
    let container_id = result
        .get("container_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OrchestratorRpcError::Protocol(
                "create_agent_persona response missing container_id".to_string(),
            )
        })?
        .to_string();
    // Parse the daemon-minted bridge client bundle if present.
    // Absent when the daemon minted persona+grant but could not mint the bundle
    // (e.g. bridge listener unconfigured); fail-soft, the worker then starts
    // without an emberd control plane.
    let bridge_bundle = result.get("bridge_client_bundle").and_then(|b| {
        Some(OrchestratorBridgeBundle {
            port: u16::try_from(b.get("port")?.as_u64()?).ok()?,
            client_cert_pem: b.get("client_cert_pem")?.as_str()?.to_string(),
            client_key_pem: b.get("client_key_pem")?.as_str()?.to_string(),
            ca_cert_pem: b.get("ca_cert_pem")?.as_str()?.to_string(),
        })
    });

    Ok(OrchestratorSpawnResult {
        persona_id,
        grant_id,
        container_id,
        bridge_bundle,
    })
}

/// Query the daemon for the currently active orchestrator persona ID.
/// Falls back gracefully so callers can display `<unknown>`.
fn daemon_query_orchestrator_persona(socket_path: &Path) -> Result<String, OrchestratorRpcError> {
    let params = json!({ "name_prefix": "orchestrator" });
    let result = call_daemon(socket_path, "list_personas", &params)?;
    // Expect an array; take the first matching entry.
    let persona_id = result
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|entry| entry.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>")
        .to_string();
    Ok(persona_id)
}

/// Revoke a Persona by ID via the daemon's `revoke_persona` RPC (best-effort).
fn daemon_revoke_persona(socket_path: &Path, persona_id: &str) -> Result<(), OrchestratorRpcError> {
    let params = json!({ "persona_id": persona_id });
    call_daemon(socket_path, "revoke_persona", &params)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Spawn checkpoint tail
// ---------------------------------------------------------------------------

/// Read the shared engine event log without depending on `internal-automation`.
///
/// This is a best-effort observability helper for `ember orchestrator status`.
/// Missing files, unreadable files, and malformed JSON lines are ignored so the
/// status path never fails the operator's main workflow.
fn tail_engine_events_silent(n: usize) -> Vec<Value> {
    let Ok(root) = core_construct_runtime::layout::primary_worktree_root() else {
        return Vec::new();
    };
    let path = root.join(core_construct_runtime::layout::ENGINE_EVENTS_FILE);
    tail_jsonl_file_silent(&path, n)
}

fn tail_jsonl_file_silent(path: &Path, n: usize) -> Vec<Value> {
    if n == 0 {
        return Vec::new();
    }
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    let mut tail: std::collections::VecDeque<Value> = std::collections::VecDeque::new();
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        tail.push_back(value);
        if tail.len() > n {
            tail.pop_front();
        }
    }
    tail.into_iter().collect()
}

/// Format one spawn checkpoint JSON event as a human-readable terminal line.
///
/// Output shape (matches the brief's display contract):
/// ```text
///   [2026-05-13T01:00:12Z] docker_run_requested ✓
///   [2026-05-13T01:00:18Z] ember_exec_ready ✗ (mount failed: no such file)
/// ```
fn format_checkpoint_line(v: &Value) -> Option<String> {
    let ts = v.get("ts").and_then(Value::as_str).unwrap_or("?");
    let kind = v.get("kind").and_then(Value::as_str)?;
    let outcome = v.get("outcome").and_then(Value::as_str)?;

    let status_glyph = if outcome == "ok" { "✓" } else { "✗" };

    let suffix = if outcome != "ok" {
        if let Some(reason) = v.get("reason").and_then(Value::as_str) {
            format!(" ({reason})")
        } else {
            String::new()
        }
    } else {
        // For ok variants with extra fields (container_id, persona_id) include them.
        let mut extras: Vec<String> = Vec::new();
        if let Some(id) = v.get("container_id").and_then(Value::as_str) {
            extras.push(format!("id={id}"));
        }
        if let Some(pid) = v.get("persona_id").and_then(Value::as_str) {
            extras.push(format!("persona={pid}"));
        }
        if extras.is_empty() {
            String::new()
        } else {
            format!(" ({})", extras.join(", "))
        }
    };

    Some(format!("  [{ts}] {kind} {status_glyph}{suffix}"))
}

/// Format one `proxy_call` JSON event as a human-readable terminal line.
///
/// Output shape (Beat 4 SCION × Emberlink demo 2026-05-15):
/// ```text
///   [proxy worker-a] POST /v1/messages — 200 — 312 tokens — Receipt <receipt-id>
/// ```
///
/// The short tag inside `[proxy ...]` is the persona's prefix (everything
/// before the first `-`, e.g. `worker-a-...` → `worker-a`) so the demo
/// stream stays readable when a long UUID-like persona id is in play.
/// Falls back to the full id if no `-` is present.
fn format_proxy_call_line(v: &Value) -> Option<String> {
    let method = v.get("method").and_then(Value::as_str)?;
    let path = v.get("path").and_then(Value::as_str)?;
    let status = v.get("status").and_then(Value::as_u64)?;
    let tokens_in = v.get("tokens_in").and_then(Value::as_u64).unwrap_or(0);
    let tokens_out = v.get("tokens_out").and_then(Value::as_u64).unwrap_or(0);
    let tokens_total = tokens_in.saturating_add(tokens_out);
    let receipt_id = v
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("receipt-?");
    let persona_id = v.get("agent_id").and_then(Value::as_str).unwrap_or("?");
    // Short tag: persona prefix up to first `-`, or the full string if
    // no `-` separator. Keeps demo lines readable when persona IDs are
    // UUID-like (the orchestrator persona is `orchestrator-<uuid>`).
    let short_tag = persona_id.split('-').next().unwrap_or(persona_id);

    Some(format!(
        "  [proxy {short_tag}] {method} {path} — {status} — {tokens_total} tokens — Receipt {receipt_id}"
    ))
}

/// Read the daemon event log and print formatted lines for spawn checkpoint
/// and proxy_call events matching `agent_id`. Errors and missing files are
/// silently ignored (this is a best-effort observability path; the caller's
/// main work is done).
fn print_spawn_checkpoints(agent_id: &str) {
    let events = tail_engine_events_silent(1000);
    let checkpoints: Vec<&Value> = events
        .iter()
        .filter(|v| {
            v.get("event").and_then(Value::as_str) == Some("spawn_checkpoint")
                && v.get("agent_id").and_then(Value::as_str) == Some(agent_id)
        })
        .collect();
    let proxy_calls: Vec<&Value> = events
        .iter()
        .filter(|v| {
            v.get("event").and_then(Value::as_str) == Some("proxy_call")
                && v.get("agent_id").and_then(Value::as_str) == Some(agent_id)
        })
        .collect();

    if !checkpoints.is_empty() {
        println!("\nSpawn checkpoints:");
        for v in &checkpoints {
            if let Some(line) = format_checkpoint_line(v) {
                println!("{line}");
            }
        }
    }

    if !proxy_calls.is_empty() {
        println!("\nProxy calls:");
        for v in &proxy_calls {
            if let Some(line) = format_proxy_call_line(v) {
                println!("{line}");
            }
        }
    }
}

/// Streaming form of `print_spawn_checkpoints` — used by Beat 3 of the
/// SCION demo. Polls the event log every 500ms; prints new spawn-checkpoint
/// events as they appear, deduped against a seen-set. Returns when
/// `timeout_secs` elapses; otherwise the operator stops it manually.
///
/// Also matches `event=="proxy_call"` so per-request proxy log lines emitted
/// by ember-proxy (Beat 4) flow into the same stream — useful when the
/// operator keeps `status --follow` running through Beat 4's narration.
async fn stream_spawn_checkpoints(agent_id: &str, timeout_secs: u64) {
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    println!("\nSpawn checkpoints (streaming, timeout {timeout_secs}s):");

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut seen: HashSet<String> = HashSet::new();

    loop {
        let events = tail_engine_events_silent(1000);
        for v in events.iter() {
            let event_kind = v.get("event").and_then(Value::as_str).unwrap_or("");
            let matches_agent = v.get("agent_id").and_then(Value::as_str) == Some(agent_id);
            if !matches_agent {
                continue;
            }
            // Dedup key: full JSON string. Cheap enough at 1000-event scale.
            let key = v.to_string();
            if seen.contains(&key) {
                continue;
            }
            match event_kind {
                "spawn_checkpoint" => {
                    if let Some(line) = format_checkpoint_line(v) {
                        println!("{line}");
                    }
                    seen.insert(key);
                }
                "proxy_call" => {
                    // Beat 4 shape — best-effort renderer; Beat 4 worker
                    // owns the canonical formatter. Fallback to raw JSON
                    // if fields missing.
                    let method = v.get("method").and_then(Value::as_str).unwrap_or("?");
                    let path = v.get("path").and_then(Value::as_str).unwrap_or("?");
                    let status = v.get("status").and_then(Value::as_u64).unwrap_or(0);
                    let tokens_in = v.get("tokens_in").and_then(Value::as_u64).unwrap_or(0);
                    let tokens_out = v.get("tokens_out").and_then(Value::as_u64).unwrap_or(0);
                    let receipt_id = v.get("receipt_id").and_then(Value::as_str).unwrap_or("-");
                    let agent_short = &agent_id[..agent_id.len().min(12)];
                    println!(
                        "[proxy {agent_short}] {method} {path} — {status} — {} tokens — Receipt {receipt_id}",
                        tokens_in + tokens_out
                    );
                    seen.insert(key);
                }
                _ => {}
            }
        }

        if Instant::now() >= deadline {
            println!("(stream timeout reached)");
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Inner form of `cmd_orchestrator_status` for testing: accepts a
/// pre-built slice of JSONL event values instead of reading from disk.
/// Returns the formatted lines for both `spawn_checkpoint` and
/// `proxy_call` events that match `agent_id`, in the order they appear
/// in the input.
#[cfg(test)]
fn cmd_orchestrator_status_inner(events: &[Value], agent_id: &str) -> Vec<String> {
    events
        .iter()
        .filter(|v| {
            let kind = v.get("event").and_then(Value::as_str);
            let matches_agent = v.get("agent_id").and_then(Value::as_str) == Some(agent_id);
            matches_agent && matches!(kind, Some("spawn_checkpoint") | Some("proxy_call"))
        })
        .filter_map(|v| match v.get("event").and_then(Value::as_str) {
            Some("spawn_checkpoint") => format_checkpoint_line(v),
            Some("proxy_call") => format_proxy_call_line(v),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// T1 — flock prevents two concurrent orchestrators.
    ///
    /// Acquires the flock on a temp file, then verifies that a second
    /// acquire attempt on the same path returns `Err(FlockError::Contended)`.
    #[test]
    fn test_flock_prevents_concurrent_orchestrator() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join("orchestrator.lock");

        // First acquire — must succeed.
        let guard = FlockGuard::acquire_nb(&lock_path).expect("first acquire should succeed");

        // Second acquire — must be contended.
        let result = FlockGuard::acquire_nb(&lock_path);
        assert!(
            matches!(result, Err(FlockError::Contended)),
            "second acquire should be contended, got: {result:?}"
        );

        // Dropping the first guard releases the lock.
        drop(guard);

        // After release, a third acquire should succeed again.
        let _guard2 =
            FlockGuard::acquire_nb(&lock_path).expect("post-release acquire should succeed");
    }

    /// T1 — max_depth validates the [1, 8] range.
    ///
    /// The async function is not called here (no runtime needed for the
    /// validation logic we are testing); instead we replicate the guard
    /// inline so the test stays synchronous and dependency-free.
    #[test]
    fn test_max_depth_validates_range() {
        // Inline the same check used in cmd_orchestrator_spawn.
        fn check(max_depth: u8) -> bool {
            max_depth != 0 && max_depth <= 8
        }

        // Valid range.
        for d in 1u8..=8 {
            assert!(check(d), "depth {d} should be valid");
        }

        // Invalid: 0.
        assert!(!check(0), "depth 0 should be rejected");

        // Invalid: 9 and above (wrapping check via > 8 guard).
        assert!(!check(9), "depth 9 should be rejected");
        assert!(!check(255), "depth 255 should be rejected");
    }

    /// T1 — verbose status prints one formatted line per spawn checkpoint event.
    ///
    /// Feeds mock JSONL events to `cmd_orchestrator_status_inner` and asserts
    /// that the output lines match the expected terminal format.
    #[test]
    fn cmd_orchestrator_status_verbose_prints_checkpoint_lines() {
        let events = vec![
            serde_json::json!({
                "event": "spawn_checkpoint",
                "kind": "docker_run_requested",
                "agent_id": "persona-aaa",
                "outcome": "ok",
                "ts": "2026-05-13T01:00:12Z"
            }),
            serde_json::json!({
                "event": "spawn_checkpoint",
                "kind": "container_created",
                "container_id": "abc123",
                "agent_id": "persona-aaa",
                "outcome": "ok",
                "ts": "2026-05-13T01:00:14Z"
            }),
            serde_json::json!({
                "event": "spawn_checkpoint",
                "kind": "ember_exec_ready",
                "agent_id": "persona-aaa",
                "outcome": "err",
                "reason": "mount failed: no such file",
                "ts": "2026-05-13T01:00:18Z"
            }),
            // Different agent_id — must be excluded.
            serde_json::json!({
                "event": "spawn_checkpoint",
                "kind": "sciontool_alive",
                "agent_id": "persona-other",
                "outcome": "ok",
                "ts": "2026-05-13T01:00:16Z"
            }),
        ];

        let lines = cmd_orchestrator_status_inner(&events, "persona-aaa");

        assert_eq!(lines.len(), 3, "expected 3 matching lines, got: {lines:?}");

        assert!(
            lines[0].contains("docker_run_requested") && lines[0].contains('✓'),
            "line 0: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("container_created") && lines[1].contains("id=abc123"),
            "line 1: {}",
            lines[1]
        );
        assert!(
            lines[2].contains("ember_exec_ready")
                && lines[2].contains('✗')
                && lines[2].contains("mount failed: no such file"),
            "line 2: {}",
            lines[2]
        );
    }

    // ---------------------------------------------------------------------------
    // Approval flow tests (three-branch: approved / denied / timed_out)
    // ---------------------------------------------------------------------------

    /// Helper: spawn a Unix domain socket server that accepts one connection,
    /// writes `response_json` as a newline-terminated JSON string, then exits.
    /// Returns the socket path inside a temp dir so the caller can connect.
    fn one_shot_daemon_server(
        dir: &tempfile::TempDir,
        response_json: serde_json::Value,
    ) -> std::path::PathBuf {
        use std::io::Write as _;
        let socket_path = dir.path().join("daemon.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind test socket");

        let resp = serde_json::to_string(&response_json).expect("serialize response");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain the request line so the client's write_all completes.
                use std::io::BufRead as _;
                let mut r = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut _line = String::new();
                let _ = r.read_line(&mut _line);
                // Send the canned response.
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(b"\n");
            }
        });

        socket_path
    }

    /// `daemon_await_grant_approval` returns `Ok(())`
    /// when the daemon resolves the approval as `approved`.
    #[test]
    fn daemon_await_grant_approval_approved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = one_shot_daemon_server(
            &dir,
            serde_json::json!({
                "id": "orchestrator-await-approval",
                "result": {
                    "decision": { "kind": "approved" }
                }
            }),
        );

        let result = daemon_await_grant_approval(&socket_path, "persona-test", "approval-ok");
        assert!(result.is_ok(), "expected Ok(()), got: {result:?}");
    }

    /// `daemon_await_grant_approval` returns
    /// `Err(ApprovalDenied)` when the daemon resolves as `denied`.
    #[test]
    fn daemon_await_grant_approval_denied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = one_shot_daemon_server(
            &dir,
            serde_json::json!({
                "id": "orchestrator-await-approval",
                "result": {
                    "decision": {
                        "kind": "denied",
                        "reason": "operator declined"
                    }
                }
            }),
        );

        let result = daemon_await_grant_approval(&socket_path, "persona-test", "approval-deny");
        match result {
            Err(OrchestratorRpcError::ApprovalDenied {
                approval_id,
                reason,
            }) => {
                assert_eq!(approval_id, "approval-deny");
                assert!(
                    reason.contains("operator declined"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected ApprovalDenied, got: {other:?}"),
        }
    }

    /// `daemon_await_grant_approval` returns
    /// `Err(ApprovalTimedOut)` when the daemon resolves as `timed_out`.
    #[test]
    fn daemon_await_grant_approval_timed_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = one_shot_daemon_server(
            &dir,
            serde_json::json!({
                "id": "orchestrator-await-approval",
                "result": {
                    "decision": { "kind": "timed_out" }
                }
            }),
        );

        let result = daemon_await_grant_approval(&socket_path, "persona-test", "approval-timeout");
        match result {
            Err(OrchestratorRpcError::ApprovalTimedOut { approval_id, .. }) => {
                assert_eq!(approval_id, "approval-timeout");
            }
            other => panic!("expected ApprovalTimedOut, got: {other:?}"),
        }
    }

    #[test]
    fn orchestrator_guidance_maps_missing_presence() {
        let guidance = orchestrator_guidance_for_rpc(
            -32001,
            r#"{"error":"authority_class_not_met","reason":"missing"}"#,
        )
        .expect("expected guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    #[test]
    fn orchestrator_guidance_maps_locked_session() {
        let guidance = orchestrator_guidance_for_rpc(
            -32030,
            "orchestrator_root denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts",
        )
        .expect("expected guidance");
        assert!(guidance.contains("operator presence"));
        assert!(guidance.contains("managed separate-uid biometric unlock"));
        assert!(guidance.contains("EMBER_VAULT_PASSPHRASE"));
    }

    /// Beat 4 — proxy_call events render as the demo's display line.
    ///
    /// The orchestrator status tail must surface `proxy_call` events
    /// alongside `spawn_checkpoint`s so the demo audience sees
    /// "agent talked to Anthropic" without a separate dashboard.
    #[test]
    fn cmd_orchestrator_status_renders_proxy_call_lines() {
        let receipt_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other_receipt_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let events = vec![
            serde_json::json!({
                "event": "spawn_checkpoint",
                "kind": "orchestrator_agent_ready",
                "persona_id": "worker-a",
                "agent_id": "worker-a",
                "outcome": "ok",
                "ts": "2026-05-15T10:00:01Z"
            }),
            serde_json::json!({
                "event": "proxy_call",
                "agent_id": "worker-a",
                "persona_id": "worker-a",
                "grant_id": "g-123",
                "method": "POST",
                "path": "/v1/messages",
                "status": 200,
                "tokens_in": 120,
                "tokens_out": 192,
                "receipt_id": receipt_id,
                "ts": "2026-05-15T10:00:03Z"
            }),
            // Different agent — must be excluded from worker-a's view.
            serde_json::json!({
                "event": "proxy_call",
                "agent_id": "worker-b",
                "persona_id": "worker-b",
                "grant_id": "g-456",
                "method": "POST",
                "path": "/v1/messages",
                "status": 200,
                "tokens_in": 10,
                "tokens_out": 20,
                "receipt_id": other_receipt_id,
                "ts": "2026-05-15T10:00:04Z"
            }),
        ];

        let lines = cmd_orchestrator_status_inner(&events, "worker-a");

        assert_eq!(lines.len(), 2, "expected 2 worker-a lines, got: {lines:?}");
        assert!(
            lines[0].contains("orchestrator_agent_ready"),
            "checkpoint first: {}",
            lines[0]
        );
        // 120+192 = 312 tokens; demo display string from the brief.
        let expected_receipt = format!("Receipt {receipt_id}");
        assert!(
            lines[1].contains("[proxy worker]")
                && lines[1].contains("POST /v1/messages")
                && lines[1].contains("200")
                && lines[1].contains("312 tokens")
                && lines[1].contains(&expected_receipt),
            "proxy_call line: {}",
            lines[1]
        );
    }

    /// materialize_bridge_client_cert_for_container creates
    /// a per-container subdirectory and writes the three daemon-minted bundle
    /// PEMs with the correct names and exact content.
    #[test]
    fn materialize_bridge_client_cert_writes_daemon_minted_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_pem = format!("{}PRIVATE KEY-----\nKEY\n{}PRIVATE KEY-----\n", "-----BEGIN ", "-----END ");
        let result = materialize_bridge_client_cert_for_container(
            "test-container-id",
            dir.path(),
            "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n",
            &key_pem,
            "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        );
        let cert = result.expect("materialize should succeed");

        // All three paths must exist under <output_dir>/<container_id>/.
        assert!(
            cert.cert_path.exists(),
            "client.crt must exist: {:?}",
            cert.cert_path
        );
        assert!(
            cert.key_path.exists(),
            "client.key must exist: {:?}",
            cert.key_path
        );
        assert!(
            cert.ca_path.exists(),
            "client-ca.crt must exist: {:?}",
            cert.ca_path
        );

        // File names must be as specified.
        assert_eq!(cert.cert_path.file_name().unwrap(), "client.crt");
        assert_eq!(cert.key_path.file_name().unwrap(), "client.key");
        assert_eq!(cert.ca_path.file_name().unwrap(), "client-ca.crt");

        // Content must be the daemon-minted PEMs, written verbatim.
        let crt_content = std::fs::read_to_string(&cert.cert_path).unwrap();
        assert_eq!(
            crt_content,
            "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n"
        );
        let key_content = std::fs::read_to_string(&cert.key_path).unwrap();
        assert_eq!(key_content, key_pem);
        let ca_content = std::fs::read_to_string(&cert.ca_path).unwrap();
        assert_eq!(
            ca_content,
            "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"
        );

        // Key file must be private (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cert.key_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "client.key must be 0600");
        }
    }

    /// orchestrator_lock_path returns a /tmp path keyed to the
    /// invoking uid, not a path inside ~/.ember/.
    ///
    /// Under ADR 131 the daemon owns ~/.ember/ (chowned to ember:ember-clients).
    /// The operator uid must be able to create the lock file without elevated
    /// privileges, so the path must not be inside ~/.ember/.
    #[test]
    fn orchestrator_lock_path_is_in_tmp_not_ember_dir() {
        let path = orchestrator_lock_path().expect("lock path must resolve");
        let path_str = path.to_string_lossy();

        // Must be in /tmp, not ~/.ember/.
        assert!(
            path_str.starts_with("/tmp/"),
            "lock path must start with /tmp/, got: {path_str}"
        );

        // Must contain the invoking uid so multi-user hosts don't collide.
        let uid = unsafe { libc::getuid() };
        assert!(
            path_str.contains(&uid.to_string()),
            "lock path must contain uid {uid}, got: {path_str}"
        );

        // Must not contain .ember in any component.
        assert!(
            !path_str.contains(".ember"),
            "lock path must not contain .ember (daemon-owned dir), got: {path_str}"
        );
    }
}
