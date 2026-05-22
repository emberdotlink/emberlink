//! Docker engine client connection helper + `DockerEngineRuntime`
//! implementation of the daemon's `ContainerRuntime` contract.
//!
//! implementation-note-110 — daemon-side Docker
//! engine plumbing. `connect_docker_engine()` discovers the local engine
//! via the standard precedence chain (`DOCKER_HOST` env var → platform
//! default socket: `/var/run/docker.sock` on Unix, named pipe on
//! Windows) and returns a ready `bollard::Docker` client.
//!
//! implementation-note-394 — adds
//! [`DockerEngineRuntime`] and the `docker_engine_spawn` entry point
//! (the parent's checkpoint). `DockerEngineRuntime` implements the local
//! [`ContainerRuntime`] trait by composing a bollard `Config` /
//! `HostConfig` from a [`SpawnSpec`], calling
//! `Docker::create_container` + `start_container`, and returning a
//! [`SpawnedContainer`] handle. Labels (`emberlink.persona_id`,
//! `emberlink.agent_uuid`, `emberlink.task_id`, `emberlink.created_at`)
//! are attached at create time so later reconciler queries can filter
//! by persona / agent / task / age without keeping daemon-side state.
//!
//! The `ContainerRuntime` trait declared here is a stop-gap local
//! definition — implementation-note-395 will hoist it
//! into `crates/ember-daemon/src/spawn/runtime.rs` as the canonical
//! cross-backend contract (with `bind_mount_uds`, `drain`, and
//! `state_report` methods alongside `spawn`). The local trait here
//! keeps Slice B compilable without taking a dependency on the
//! still-unlanded Slice A module.
//!
//! Why this lives in the daemon (not in ember-construct):
//!   - The shim-side argv classifier in `ember-construct::docker`
//!     translates `docker <verb>` argv into action keys; that's a
//!     pure-function tree-walk with no network surface.
//!   - The DAEMON is what actually mediates a Docker engine call once
//!     a Construct invocation lands at the broker. That mediation
//!     requires an authenticated engine client, which bollard provides.
//!   - Keeping bollard out of the shim binary keeps shim build times
//!     fast and avoids shipping a Docker SDK into every user-launched
//!     ember-docker process.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::models::{ContainerStateStatusEnum, HostConfig, Mount, MountTypeEnum};
use chrono::Utc;

/// Connect to the local Docker engine using standard discovery.
///
/// Resolution order (delegated to bollard's `connect_with_local_defaults`):
///   1. `DOCKER_HOST` environment variable, if set. Supports
///      `unix://`, `tcp://`, and `npipe://` (Windows) schemes.
///   2. Platform default:
///      - Unix (Linux, macOS): `unix:///var/run/docker.sock`
///      - Windows: `npipe:////./pipe/docker_engine`
///
/// On macOS, Docker Desktop installs a forwarder at
/// `/var/run/docker.sock` (a symlink to the user-scoped socket the
/// engine actually listens on), so the Unix default works without any
/// extra configuration. Other engines (colima, Rancher Desktop, OrbStack)
/// either replicate that symlink or expect the user to set `DOCKER_HOST`
/// — the standard discovery picks both up.
///
/// Returns a configured `Docker` client. The constructor itself is
/// non-blocking and does NOT verify reachability — call `client.ping()`
/// or one of the API methods to confirm the engine is actually running.
pub fn connect_docker_engine() -> Result<Docker> {
    Docker::connect_with_local_defaults()
        .context("failed to construct Docker engine client from local defaults (DOCKER_HOST env / platform default socket)")
}

/// Errors raised by [`ContainerRuntime::spawn`] implementations.
///
/// Each variant carries enough provenance that the broker-side caller
/// can produce a typed `spawn-failed` event without re-parsing the
/// underlying engine error. New variants must be additive — adding a
/// fallthrough `Other` widens the trust surface for downstream callers
/// that pattern-match on the specific failure mode.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeSpawnError {
    /// The runtime client could not be reached at all (engine socket
    /// down, `DOCKER_HOST` misconfigured, named pipe missing on
    /// Windows). The wrapped error carries the underlying bollard
    /// transport context.
    #[error("docker engine unreachable: {0}")]
    EngineUnreachable(bollard::errors::Error),
    /// The engine accepted the create call but returned a non-OK
    /// response (image pull failed, name conflict, invalid config,
    /// resource limit refused).
    #[error("docker create_container failed: {0}")]
    CreateFailed(bollard::errors::Error),
    /// The container was created successfully but `start_container`
    /// failed (entrypoint missing, kernel rejected the mount table,
    /// out of memory). The caller can use the returned container id
    /// to clean up via `Docker::remove_container`.
    #[error("docker start_container failed (container_id={container_id}): {source}")]
    StartFailed {
        /// The opaque container id returned from `create_container`
        /// before `start_container` rejected the launch.
        container_id: String,
        /// Underlying bollard error.
        #[source]
        source: bollard::errors::Error,
    },
    /// Caller supplied a [`SpawnSpec`] that failed local validation
    /// (e.g. an `image` field that is empty). Validation runs BEFORE
    /// touching the engine so a malformed spec produces a typed error
    /// rather than a confusing engine-side rejection.
    #[error("invalid spawn spec: {0}")]
    InvalidSpec(String),
    /// `Docker::stop_container` failed (container missing, engine
    /// rejected the stop, or the grace window elapsed without the
    /// container exiting). Surfaced by [`ContainerRuntime::drain`].
    #[error("docker stop_container failed (container_id={container_id}): {source}")]
    StopFailed {
        /// The container id that was being drained.
        container_id: String,
        /// Underlying bollard error.
        #[source]
        source: bollard::errors::Error,
    },
    /// `Docker::inspect_container` failed (container missing, engine
    /// rejected the inspect call). Surfaced by [`ContainerRuntime::drain`]
    /// (during post-stop verification) and
    /// [`ContainerRuntime::state_report`].
    #[error("docker inspect_container failed (container_id={container_id}): {source}")]
    InspectFailed {
        /// The container id that was being inspected.
        container_id: String,
        /// Underlying bollard error.
        #[source]
        source: bollard::errors::Error,
    },
    /// [`ContainerRuntime::drain`] called `stop_container` successfully
    /// and then re-inspected the container, but the engine reported a
    /// state other than `exited` / `dead` within the grace window. This
    /// indicates the container did not actually halt — e.g. the kernel
    /// failed to deliver `SIGKILL` or a parent reaper retained it. The
    /// caller should escalate (force-remove, alert).
    #[error("docker drain did not produce exited state (container_id={container_id}, observed={observed})")]
    DrainNotExited {
        /// The container id that failed to exit.
        container_id: String,
        /// The state reported by `inspect_container` after `stop_container`.
        /// Stored as the lowercased string form so downstream events
        /// don't need to know the bollard enum.
        observed: String,
    },
}

/// Declarative spec consumed by [`ContainerRuntime::spawn`].
///
/// Each field is platform-agnostic and gets translated into the
/// backend's native vocabulary inside the runtime impl. Adding new
/// fields requires a default so existing call sites keep compiling.
///
/// **Stop-gap module location:** Slice A
/// (implementation-note-395) will hoist this struct
/// into a cross-backend module; the local definition here keeps Slice B
/// compilable in isolation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpawnSpec {
    /// Container image to launch (e.g. `"ubuntu:24.04"`). Required —
    /// an empty string is rejected by [`SpawnSpec::validate`].
    pub image: String,
    /// Optional name to assign to the container. Falls back to the
    /// engine's auto-generated name when `None`.
    pub name: Option<String>,
    /// Persona id label (`emberlink.persona_id`). Empty string means
    /// "not associated with a specific persona" — the label is still
    /// emitted so reconcilers can distinguish "no persona" from
    /// "label missing entirely" (which would indicate a non-emberd
    /// container).
    pub persona_id: String,
    /// Agent UUID label (`emberlink.agent_uuid`). Same posture as
    /// `persona_id` — emitted unconditionally as an empty string when
    /// the spawn is not tied to a SCION agent.
    pub agent_uuid: String,
    /// Task id label (`emberlink.task_id`). Filled in by the caller for
    /// broker-mediated spawns so a `docker ps -f label=emberlink.task_id=...`
    /// query maps containers back to the originating task.
    pub task_id: String,
    /// Additional caller-supplied labels. Merged into the final label
    /// set AFTER the four canonical `emberlink.*` labels so caller
    /// labels cannot shadow the canonical ones.
    pub labels: HashMap<String, String>,
    /// Environment variables (`KEY=VALUE` form, matching the Docker
    /// engine wire format). Pass empty when the image's default env is
    /// sufficient.
    pub env: Vec<String>,
    /// Override the image entrypoint. `None` leaves the image default.
    pub entrypoint: Option<Vec<String>>,
    /// Command/args to run. `None` falls back to the image default.
    pub cmd: Option<Vec<String>>,
    /// Per-agent UDS sockets to bind-mount into the container. Each
    /// entry produces a bollard `Mount` with `Type=bind` so the agent
    /// inside the container can `connect()` to emberd. The list runs
    /// through the engine's HostConfig.Mounts (NOT HostConfig.Binds)
    /// so we get explicit `Type=bind` + `ReadOnly` semantics; legacy
    /// `Binds` strings don't carry that posture in a portable way.
    pub uds_mounts: Vec<UdsBindMount>,
}

/// One UDS socket bind-mount entry.
///
/// Matches the two-entry posture produced by
/// [`crate::spawn::scion::scion_mount_table_for_socket`]: callers stage
/// the parent dir RO and the per-agent socket inode RW, then map each
/// of those onto a [`UdsBindMount`] before handing the spec to
/// [`DockerEngineRuntime::spawn`].
///
/// The `read_only` field controls whether the bind-mount is created
/// RW or RO inside the container. The SCION trust-surface invariant
/// is: parent dir RO, socket inode RW — see `spawn/scion.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdsBindMount {
    /// Host-side path of the socket (or parent dir) being mounted in.
    pub host_path: PathBuf,
    /// Path inside the container where the socket (or parent dir)
    /// should appear.
    pub container_path: PathBuf,
    /// Read-only posture. `true` produces a bind-mount with
    /// `ReadOnly=true` in the engine wire form.
    pub read_only: bool,
}

impl SpawnSpec {
    /// Validate the spec before any engine roundtrip.
    ///
    /// Only enforces the minimum invariants that protect the engine
    /// from a clearly malformed call. Stronger policy (image allow-list,
    /// label allow-list, label value validation) lives in the broker
    /// path that constructs the spec, not here.
    fn validate(&self) -> Result<(), RuntimeSpawnError> {
        if self.image.trim().is_empty() {
            return Err(RuntimeSpawnError::InvalidSpec(
                "image must be non-empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Compose the final label map: the four canonical `emberlink.*`
    /// labels followed by the caller-supplied labels. Caller labels
    /// cannot overwrite the canonical ones — the canonical insert runs
    /// LAST so a same-key collision keeps the canonical value.
    fn final_labels(&self) -> HashMap<String, String> {
        let mut out: HashMap<String, String> = self.labels.clone();
        out.insert("emberlink.persona_id".to_string(), self.persona_id.clone());
        out.insert("emberlink.agent_uuid".to_string(), self.agent_uuid.clone());
        out.insert("emberlink.task_id".to_string(), self.task_id.clone());
        out.insert("emberlink.created_at".to_string(), Utc::now().to_rfc3339());
        out
    }
}

/// Handle returned by a successful [`ContainerRuntime::spawn`].
///
/// `container_id` is the engine-assigned opaque id (NOT the
/// caller-supplied name). Callers persist this id for later
/// `inspect` / `stop` / `remove` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnedContainer {
    /// Engine-assigned container id (sha256 hex prefix, typically 64
    /// chars). Stable across the container's lifetime.
    pub container_id: String,
    /// Final name the engine assigned. Echoes `SpawnSpec::name` when
    /// the caller supplied one, otherwise the engine's auto-generated
    /// name (e.g. `silly_einstein`).
    pub name: Option<String>,
}

/// High-level lifecycle state observed by
/// [`ContainerRuntime::state_report`]. Maps the engine's verbose
/// status vocabulary into the three states the reconciler cares about.
///
/// The mapping is intentionally lossy — `Running` covers both
/// `created` and `running` (the container exists and may serve work),
/// `Draining` covers `restarting` / `removing` / `paused` (a lifecycle
/// transition is in flight), and `Dead` covers `exited` / `dead` /
/// missing-state (the container is no longer serving work). The
/// reconciler does not need finer-grained vocabulary to decide whether
/// to keep, drain, or replace a container.
///
/// implementation-note-99 — added alongside
/// [`docker_engine_drain`] / [`docker_engine_state_report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// The container is alive: `created` (start scheduled) or `running`
    /// (entrypoint executing).
    Running,
    /// A lifecycle transition is in flight: `restarting`, `removing`,
    /// or `paused`. The container is not currently serving work but is
    /// not terminal either; callers typically wait + re-inspect.
    Draining,
    /// The container is terminal: `exited` (process returned) or
    /// `dead` (engine declared it unrecoverable). Also returned when
    /// `inspect_container` reports no state at all — the engine has
    /// effectively forgotten the container.
    Dead,
}

impl RuntimeState {
    /// Map a bollard [`ContainerStateStatusEnum`] into a
    /// [`RuntimeState`]. The `EMPTY` variant maps to [`Dead`] —
    /// reading "no state at all" as "terminal" is the safest posture
    /// for the reconciler (treat as "needs replacement").
    pub fn from_engine_status(status: ContainerStateStatusEnum) -> Self {
        match status {
            ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::RUNNING => {
                Self::Running
            }
            ContainerStateStatusEnum::RESTARTING
            | ContainerStateStatusEnum::REMOVING
            | ContainerStateStatusEnum::PAUSED => Self::Draining,
            ContainerStateStatusEnum::EXITED
            | ContainerStateStatusEnum::DEAD
            | ContainerStateStatusEnum::EMPTY => Self::Dead,
        }
    }
}

/// Local definition of the container-runtime contract.
///
/// **Stop-gap:** the canonical cross-backend definition lands in
/// `crates/ember-daemon/src/spawn/runtime.rs` under
/// implementation-note-395 with the full four-bullet
/// surface (`spawn`, `bind_mount_uds`, `drain`, `state_report`). The
/// trait here exposes `spawn`, `drain`, and `state_report` so Slice B
/// + D can compile against a stable contract before Slice A merges;
/// Slice A will absorb this trait into the canonical location and the
/// `DockerEngineRuntime` `impl` here will re-target the canonical trait
/// verbatim.
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    /// Spawn a container as described by `spec` and return a handle.
    ///
    /// Implementations MUST:
    ///   - validate `spec` (call [`SpawnSpec::validate`]),
    ///   - attach the canonical labels (call [`SpawnSpec::final_labels`]),
    ///   - apply each [`UdsBindMount`] as a bind-mount in the
    ///     backend's native vocabulary.
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError>;

    /// Stop the container identified by `container_id`, giving the
    /// entrypoint up to `grace` to exit gracefully before the engine
    /// escalates to `SIGKILL`. Verifies the container reached a
    /// terminal state (`exited` / `dead`) before returning success.
    ///
    /// Implementations MUST:
    ///   - call the engine's stop primitive with the grace timeout,
    ///   - re-inspect the container after stop returns and reject
    ///     anything other than [`RuntimeState::Dead`] with
    ///     [`RuntimeSpawnError::DrainNotExited`].
    ///
    /// implementation-note-99.
    async fn drain(
        &self,
        container_id: &str,
        grace: Duration,
    ) -> Result<(), RuntimeSpawnError>;

    /// Inspect the container and return its lifecycle state in the
    /// reconciler's three-state vocabulary.
    ///
    /// Implementations MUST call the engine's inspect primitive and
    /// fold the resulting status string through
    /// [`RuntimeState::from_engine_status`]. A container with no
    /// state populated in the inspect response is reported as
    /// [`RuntimeState::Dead`] — see [`RuntimeState::from_engine_status`]
    /// for the rationale.
    ///
    /// implementation-note-99.
    async fn state_report(
        &self,
        container_id: &str,
    ) -> Result<RuntimeState, RuntimeSpawnError>;
}

/// `ContainerRuntime` implementation backed by the local Docker engine
/// via bollard. Works against any Docker-engine-compatible backend
/// (Docker Desktop, OrbStack-as-Docker-backend, colima, Rancher
/// Desktop) — engine discovery is delegated to bollard's
/// `connect_with_local_defaults` (see [`connect_docker_engine`]).
///
/// The struct owns a single `bollard::Docker` client. `Docker` is
/// internally `Arc`-shared so cloning `DockerEngineRuntime` is cheap
/// and safe across `tokio::spawn` boundaries.
#[derive(Debug, Clone)]
pub struct DockerEngineRuntime {
    docker: Docker,
}

impl DockerEngineRuntime {
    /// Construct a runtime backed by a pre-connected `Docker` client.
    /// Callers in production wire this from [`connect_docker_engine`];
    /// tests pass a stub by injecting a `Docker` built against a
    /// fixture URI (`unix:///tmp/...`).
    pub fn new(docker: Docker) -> Self {
        Self { docker }
    }

    /// Construct a runtime using the daemon's standard engine
    /// discovery ([`connect_docker_engine`]).
    pub fn connect_local() -> Result<Self> {
        Ok(Self::new(connect_docker_engine()?))
    }

    /// Access the underlying bollard client. Useful for code paths
    /// that need engine APIs outside the [`ContainerRuntime`] surface
    /// (e.g. `Docker::inspect_container`, image pull). Returning a
    /// reference rather than a clone makes the borrow shape explicit
    /// at call sites.
    pub fn docker(&self) -> &Docker {
        &self.docker
    }
}

/// Parent checkpoint for implementation-note-394.
///
/// Free function form of [`DockerEngineRuntime::spawn`]. Composes the
/// bollard `Config` from `spec`, calls `create_container` +
/// `start_container`, returns the [`SpawnedContainer`] handle.
///
/// Kept as a free function (not just a trait impl) so the
/// `target_state_anchor = "fn docker_engine_spawn"` task-level marker in
/// `release-checklist` matches a literal symbol in this module. The
/// [`ContainerRuntime`] impl below delegates to this function so there
/// is exactly one create+start code path to audit.
///
/// # Wire shape
///
/// 1. `spec.validate()` — reject empty `image` before touching engine.
/// 2. `spec.final_labels()` — produce canonical + caller labels.
/// 3. Compose `Config<String>` (image, env, entrypoint, cmd, labels,
///    `HostConfig.Mounts` for the UDS bind-mounts).
/// 4. `Docker::create_container` — POST `/containers/create`.
/// 5. `Docker::start_container` — POST `/containers/<id>/start`.
/// 6. Return [`SpawnedContainer`] with the engine-assigned id +
///    optional caller-supplied name.
///
/// # Errors
///
/// All failure modes are typed via [`RuntimeSpawnError`]:
/// `InvalidSpec` on validation failure, `CreateFailed` on the
/// create-call rejection, `StartFailed` on the start-call rejection
/// (carries the container id so cleanup is possible). The first call
/// that touches the engine (`create_container`) double-purposes as a
/// reachability probe — its error is reported as `CreateFailed`
/// rather than `EngineUnreachable` because bollard doesn't distinguish
/// "engine down" from "engine up but rejected request" at the
/// transport layer; the variant exists for callers that produce their
/// own pre-flight `ping()` and want a distinct error code.
pub async fn docker_engine_spawn(
    docker: &Docker,
    spec: SpawnSpec,
) -> Result<SpawnedContainer, RuntimeSpawnError> {
    spec.validate()?;

    let labels = spec.final_labels();

    // HostConfig.Mounts carries the UDS bind-mounts in explicit
    // `Type=bind` + `ReadOnly` form. We deliberately avoid the legacy
    // `HostConfig.Binds` string list — `Binds` encodes the read-only
    // bit as a `:ro` suffix on a colon-separated string, which is
    // brittle to parse round-trip and doesn't surface the bind-type
    // explicitly in engine inspect output.
    let mounts: Vec<Mount> = spec
        .uds_mounts
        .iter()
        .map(|m| Mount {
            target: Some(m.container_path.display().to_string()),
            source: Some(m.host_path.display().to_string()),
            typ: Some(MountTypeEnum::BIND),
            read_only: Some(m.read_only),
            ..Default::default()
        })
        .collect();

    let host_config = HostConfig {
        mounts: if mounts.is_empty() {
            None
        } else {
            Some(mounts)
        },
        ..Default::default()
    };

    let config: Config<String> = Config {
        image: Some(spec.image.clone()),
        env: if spec.env.is_empty() {
            None
        } else {
            Some(spec.env.clone())
        },
        entrypoint: spec.entrypoint.clone(),
        cmd: spec.cmd.clone(),
        labels: Some(labels),
        host_config: Some(host_config),
        ..Default::default()
    };

    let create_options = spec.name.as_ref().map(|n| CreateContainerOptions {
        name: n.clone(),
        platform: None,
    });

    let created = docker
        .create_container(create_options, config)
        .await
        .map_err(RuntimeSpawnError::CreateFailed)?;

    docker
        .start_container(&created.id, None::<StartContainerOptions<String>>)
        .await
        .map_err(|e| RuntimeSpawnError::StartFailed {
            container_id: created.id.clone(),
            source: e,
        })?;

    Ok(SpawnedContainer {
        container_id: created.id,
        name: spec.name,
    })
}

/// Parent checkpoint for implementation-note-99.
///
/// Free function form of [`DockerEngineRuntime::drain`]. Stops the
/// container with a grace window, then re-inspects it to confirm the
/// state actually transitioned to terminal (`exited` / `dead`).
///
/// Kept as a free function (not just a trait impl) so the
/// `target_state_anchor = "fn docker_engine_drain"` task-level marker in
/// `release-checklist` matches a literal symbol in this module. The
/// [`ContainerRuntime`] impl below delegates to this function so there
/// is exactly one stop+verify code path to audit.
///
/// # Wire shape
///
/// 1. `Docker::stop_container` with `StopContainerOptions { t: grace_secs }`.
///    The engine sends `SIGTERM`, waits up to `t` seconds, then
///    escalates to `SIGKILL`. On `t=0` the engine kills immediately.
/// 2. `Docker::inspect_container` (no options) to read the post-stop
///    state. We fold the status through [`RuntimeState::from_engine_status`].
/// 3. Reject any non-[`RuntimeState::Dead`] outcome with
///    [`RuntimeSpawnError::DrainNotExited`] so callers learn the
///    drain did not actually halt the workload.
///
/// # Grace conversion
///
/// `bollard::container::StopContainerOptions::t` is `i64` seconds.
/// `Duration::as_secs()` is `u64`; we saturate to `i64::MAX` on
/// overflow rather than silently truncating, but in practice any grace
/// window larger than ~292 billion years is already a caller bug.
///
/// # Errors
///
/// - [`RuntimeSpawnError::StopFailed`] — `stop_container` returned an
///   error (engine unreachable, container missing, grace exceeded).
/// - [`RuntimeSpawnError::InspectFailed`] — the post-stop inspect call
///   failed (container removed between calls, engine flaked).
/// - [`RuntimeSpawnError::DrainNotExited`] — stop succeeded and
///   inspect succeeded, but the observed state is not terminal.
pub async fn docker_engine_drain(
    docker: &Docker,
    container_id: &str,
    grace: Duration,
) -> Result<(), RuntimeSpawnError> {
    let grace_secs = i64::try_from(grace.as_secs()).unwrap_or(i64::MAX);

    docker
        .stop_container(container_id, Some(StopContainerOptions { t: grace_secs }))
        .await
        .map_err(|e| RuntimeSpawnError::StopFailed {
            container_id: container_id.to_string(),
            source: e,
        })?;

    let inspect = docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .map_err(|e| RuntimeSpawnError::InspectFailed {
            container_id: container_id.to_string(),
            source: e,
        })?;

    let observed_status = inspect
        .state
        .as_ref()
        .and_then(|s| s.status)
        .unwrap_or(ContainerStateStatusEnum::EMPTY);
    let observed = RuntimeState::from_engine_status(observed_status);

    if observed == RuntimeState::Dead {
        Ok(())
    } else {
        Err(RuntimeSpawnError::DrainNotExited {
            container_id: container_id.to_string(),
            observed: observed_status.as_ref().to_string(),
        })
    }
}

/// Parent checkpoint for implementation-note-99.
///
/// Free function form of [`DockerEngineRuntime::state_report`].
/// Inspects the container and maps the engine's `state.status` string
/// onto the reconciler's three-state vocabulary via
/// [`RuntimeState::from_engine_status`].
///
/// Kept as a free function so the trait impl has a single code path to
/// audit; the call shape mirrors [`docker_engine_drain`].
///
/// # Errors
///
/// - [`RuntimeSpawnError::InspectFailed`] — the inspect call failed
///   (container missing, engine unreachable). A container with no
///   `state` populated in the response is NOT an error — it is folded
///   into [`RuntimeState::Dead`] per [`RuntimeState::from_engine_status`].
pub async fn docker_engine_state_report(
    docker: &Docker,
    container_id: &str,
) -> Result<RuntimeState, RuntimeSpawnError> {
    let inspect = docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .map_err(|e| RuntimeSpawnError::InspectFailed {
            container_id: container_id.to_string(),
            source: e,
        })?;

    let status = inspect
        .state
        .as_ref()
        .and_then(|s| s.status)
        .unwrap_or(ContainerStateStatusEnum::EMPTY);

    Ok(RuntimeState::from_engine_status(status))
}

#[async_trait]
impl ContainerRuntime for DockerEngineRuntime {
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError> {
        docker_engine_spawn(&self.docker, spec).await
    }

    async fn drain(
        &self,
        container_id: &str,
        grace: Duration,
    ) -> Result<(), RuntimeSpawnError> {
        docker_engine_drain(&self.docker, container_id, grace).await
    }

    async fn state_report(
        &self,
        container_id: &str,
    ) -> Result<RuntimeState, RuntimeSpawnError> {
        docker_engine_state_report(&self.docker, container_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skip-gate for the two `connect_docker_engine_*` tests below.
    ///
    /// Bollard's `connect_with_local_defaults` reads either
    /// `DOCKER_HOST` or `/var/run/docker.sock`; if the socket is
    /// absent (the headless host has no Docker installed), the
    /// constructor returns an error and the tests fail. Per the
    /// daemon-crate test discipline rule
    /// (`.claude/rules/daemon.md`: "Sandbox/Docker tests gate on
    /// availability"), skip rather than fail.
    ///
    /// Mirrors the pattern used by `infra::sandbox::docker_available`
    /// — same `docker info` exit-code check — but lives here so this
    /// module's tests don't reach across into the sibling module.
    /// Anchor: `ember_daemon_broken_test_cluster_resolved`.
    fn docker_available() -> bool {
        std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// T2 fixture: happy-path construction of the engine client.
    ///
    /// `connect_with_local_defaults` is non-network in its construction
    /// phase — it only assembles the client struct based on env / OS.
    /// Reachability is not exercised here; that would require either a
    /// running engine (flaky in CI) or bollard's testkit (not currently
    /// vendored in this workspace).
    ///
    /// If a future integration test needs end-to-end engine roundtrip
    /// coverage, gate it on `#[ignore]` + a `DOCKER_E2E=1` env check
    /// rather than enabling it by default.
    #[test]
    fn connect_docker_engine_constructs_client() {
        if !docker_available() {
            eprintln!(
                "connect_docker_engine_constructs_client: Docker not available — skipping per daemon test-discipline rule"
            );
            return;
        }
        let client = connect_docker_engine();
        assert!(
            client.is_ok(),
            "Docker::connect_with_local_defaults should succeed at construction time (no engine roundtrip): {:?}",
            client.err()
        );
    }

    /// T2 fixture: explicit `DOCKER_HOST` env override is honored.
    ///
    /// Bollard reads `DOCKER_HOST` inside `connect_with_local_defaults`,
    /// so setting the env var before the call must steer the client
    /// without panicking. We use a syntactically valid but unroutable
    /// host so the construction succeeds — actual network attempts are
    /// only made on the first API call, which we never invoke here.
    ///
    /// NOTE: `std::env::set_var` is process-global and not thread-safe
    /// when other tests read the same var concurrently. Cargo test runs
    /// each `#[test]` on its own thread by default; we accept that
    /// risk here because no other test in this module touches DOCKER_HOST.
    #[test]
    fn connect_docker_engine_honors_docker_host_env() {
        if !docker_available() {
            eprintln!(
                "connect_docker_engine_honors_docker_host_env: Docker not available — skipping per daemon test-discipline rule"
            );
            return;
        }
        // SAFETY: single-purpose smoke test; no other test in this module
        // reads or writes `DOCKER_HOST`. The variable is intentionally
        // left set on exit to avoid a teardown race; cargo test isolates
        // worker processes so this does not leak between binaries.
        // SAFETY: Rust 2024 marks `env::set_var` unsafe because it can
        // race with other threads reading env. This test is intentionally
        // single-threaded with respect to DOCKER_HOST.
        unsafe {
            std::env::set_var("DOCKER_HOST", "tcp://127.0.0.1:1");
        }
        let client = connect_docker_engine();
        assert!(
            client.is_ok(),
            "client construction must succeed even with an unroutable DOCKER_HOST: {:?}",
            client.err()
        );
    }

    // -----------------------------------------------------------------
    // implementation-note-99 — drain +
    // state_report mapping tests.
    //
    // We exercise the pure mapping helpers
    // ([`RuntimeState::from_engine_status`]) plus the error-variant
    // surface added for the new methods. End-to-end roundtrips against
    // a real engine are deferred to a `DOCKER_E2E=1`-gated integration
    // test in the same posture as the existing `connect_docker_engine`
    // tests above.
    // -----------------------------------------------------------------

    /// T2 fixture: `created` and `running` engine statuses fold into
    /// [`RuntimeState::Running`]. The reconciler does not need to
    /// distinguish "start scheduled" from "entrypoint executing" — both
    /// are "alive, may serve work".
    #[test]
    fn runtime_state_running_covers_created_and_running() {
        assert_eq!(
            RuntimeState::from_engine_status(ContainerStateStatusEnum::CREATED),
            RuntimeState::Running
        );
        assert_eq!(
            RuntimeState::from_engine_status(ContainerStateStatusEnum::RUNNING),
            RuntimeState::Running
        );
    }

    /// T2 fixture: `restarting`, `removing`, and `paused` engine
    /// statuses fold into [`RuntimeState::Draining`]. These are
    /// transient states the reconciler waits on rather than acting on.
    #[test]
    fn runtime_state_draining_covers_transitional_states() {
        for status in [
            ContainerStateStatusEnum::RESTARTING,
            ContainerStateStatusEnum::REMOVING,
            ContainerStateStatusEnum::PAUSED,
        ] {
            assert_eq!(
                RuntimeState::from_engine_status(status),
                RuntimeState::Draining,
                "{status:?} should fold to Draining"
            );
        }
    }

    /// T2 fixture: `exited`, `dead`, and the empty-string checkpoint
    /// fold into [`RuntimeState::Dead`]. The empty case happens when
    /// `inspect_container` returns a response with no `state` field
    /// populated — folding that into `Dead` is the safest posture for
    /// the reconciler (treat as "needs replacement").
    #[test]
    fn runtime_state_dead_covers_terminal_and_missing() {
        for status in [
            ContainerStateStatusEnum::EXITED,
            ContainerStateStatusEnum::DEAD,
            ContainerStateStatusEnum::EMPTY,
        ] {
            assert_eq!(
                RuntimeState::from_engine_status(status),
                RuntimeState::Dead,
                "{status:?} should fold to Dead"
            );
        }
    }

    /// T2 fixture: `StopFailed` carries the container id verbatim so
    /// downstream `spawn-failed`-style events can identify which
    /// container actually failed to drain without re-parsing the
    /// underlying bollard error.
    #[test]
    fn stop_failed_carries_container_id() {
        let err = RuntimeSpawnError::StopFailed {
            container_id: "abc123".to_string(),
            source: bollard::errors::Error::APIVersionParseError {},
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("abc123"),
            "StopFailed display must include container id; got: {rendered}"
        );
    }

    /// T2 fixture: `InspectFailed` carries the container id verbatim
    /// for the same reason as `StopFailed`.
    #[test]
    fn inspect_failed_carries_container_id() {
        let err = RuntimeSpawnError::InspectFailed {
            container_id: "def456".to_string(),
            source: bollard::errors::Error::APIVersionParseError {},
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("def456"),
            "InspectFailed display must include container id; got: {rendered}"
        );
    }

    /// T2 fixture: `DrainNotExited` records both the container id and
    /// the observed status string so an operator can tell whether the
    /// container is stuck in `restarting`, `paused`, etc. without
    /// re-inspecting.
    #[test]
    fn drain_not_exited_carries_observed_state() {
        let err = RuntimeSpawnError::DrainNotExited {
            container_id: "ghi789".to_string(),
            observed: "restarting".to_string(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("ghi789"),
            "DrainNotExited display must include container id; got: {rendered}"
        );
        assert!(
            rendered.contains("restarting"),
            "DrainNotExited display must include observed state; got: {rendered}"
        );
    }

    /// T2 fixture: confirm [`DockerEngineRuntime`] can be coerced to
    /// `&dyn ContainerRuntime`. If `drain` or `state_report` is missing
    /// from either the trait or the impl, the coercion fails to compile.
    /// Runtime never touches an engine — the function pointer is taken
    /// but never invoked. End-to-end engine roundtrips are deferred to
    /// the `DOCKER_E2E=1` lane.
    #[test]
    fn docker_engine_runtime_is_container_runtime_trait_object() {
        // Both helper fns are dead at runtime by design — their
        // existence (and the trait-object coercion the inner one
        // performs) is the compile-time assertion that
        // `DockerEngineRuntime: ContainerRuntime`. The `_use_dyn`
        // path is never invoked because the comment below explains
        // we can't safely construct a `DockerEngineRuntime` in this
        // test (bollard's `connect_with_local_defaults` fails on
        // hosts without `/var/run/docker.sock`).
        #[allow(dead_code)]
        fn assert_dyn_runtime(_r: &dyn ContainerRuntime) {}
        fn _use_dyn(r: &DockerEngineRuntime) {
            assert_dyn_runtime(r);
        }
        // The function above is enough to compile-check the impl
        // surface. We do not call `_use_dyn` because constructing a
        // `DockerEngineRuntime` requires bollard's
        // `connect_with_local_defaults`, which fails in environments
        // without `/var/run/docker.sock`.
    }
}
