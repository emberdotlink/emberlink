//! Canonical container-runtime contract for daemon-owned spawn backends.
//!
//! This surface is the narrow seam shared by the current Docker-engine
//! backend, the SCION adapter layer, future Apple Container plumbing,
//! and test/noop runtimes that exercise spawn callers without a live
//! engine. The contract stays small on purpose: a declarative spawn
//! spec, optional live UDS bind-mount mutation, and the two lifecycle
//! reads the reconciler needs (`drain` + `state_report`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Supported daemon-owned container runtime backends.
///
/// The Docker-compatible baseline covers Docker Desktop,
/// OrbStack-as-Docker-backend, colima, and Rancher Desktop. Apple
/// Container and host-resident/no-container modes are accepted config
/// values so operators can express the intended runtime lane even before
/// those concrete adapters are wired in this crate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeBackend {
    /// Docker Engine-compatible API / CLI surface.
    #[default]
    DockerEngine,
    /// Apple's `container` toolchain.
    AppleContainer,
    /// No container runtime; host-resident lane.
    NoneHostResident,
}

impl RuntimeBackend {
    pub const SUPPORTED_VALUES: &'static [&'static str] =
        &["docker-engine", "apple-container", "none-host-resident"];

    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeBackend::DockerEngine => "docker-engine",
            RuntimeBackend::AppleContainer => "apple-container",
            RuntimeBackend::NoneHostResident => "none-host-resident",
        }
    }

    pub fn supported_values() -> &'static [&'static str] {
        Self::SUPPORTED_VALUES
    }

    pub fn supported_values_csv() -> &'static str {
        "docker-engine, apple-container, none-host-resident"
    }

    pub fn parse_config_value(value: &str) -> Result<Self, RuntimeBackendError> {
        match value.trim() {
            "docker-engine" => Ok(RuntimeBackend::DockerEngine),
            "apple-container" => Ok(RuntimeBackend::AppleContainer),
            "none-host-resident" => Ok(RuntimeBackend::NoneHostResident),
            other => Err(RuntimeBackendError::UnknownBackend {
                value: other.to_string(),
            }),
        }
    }

    /// Resolve the backend selected by daemon config into a runtime object.
    ///
    /// Concrete Docker/Apple adapters are intentionally not invented here:
    /// ADR 207 keeps runtime consolidation open and the daemon-side engine
    /// island was deleted. Known values therefore resolve to a typed
    /// backend placeholder that fails closed on lifecycle calls until the
    /// concrete adapter lands.
    pub fn resolve_from_config(
        config: &crate::infra::config::DaemonConfig,
    ) -> Result<Box<dyn ContainerRuntime>, RuntimeBackendError> {
        Ok(config.runtime_backend.resolve())
    }

    pub fn resolve(self) -> Box<dyn ContainerRuntime> {
        Box::new(ConfiguredRuntime { backend: self })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeBackendError {
    #[error(
        "unsupported runtime backend '{value}'; supported values: {}",
        RuntimeBackend::supported_values_csv()
    )]
    UnknownBackend { value: String },
}

/// Errors raised by [`ContainerRuntime`] implementations.
///
/// The variants stay additive so backend-specific call sites can
/// pattern-match without widening the trust surface through a catch-all
/// transport error. Backend-specific transport/lifecycle failures are
/// each backend's own concern — the bollard-typed variants were removed
/// with the bollard engine island (ADR 207 seam 7); a future
/// `ContainerRuntime` backend extends this enum with its own
/// (non-`bollard`) error vocabulary when it lands.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeSpawnError {
    /// Caller supplied a [`SpawnSpec`] that failed local validation.
    #[error("invalid spawn spec: {0}")]
    InvalidSpec(String),
    /// The backend does not support the requested operation.
    #[error("runtime operation unsupported: {operation}")]
    UnsupportedOperation {
        /// Short operation label, e.g. `bind_mount_uds`.
        operation: &'static str,
    },
    /// The selected backend is recognized, but no concrete adapter is
    /// linked for that backend in this daemon build.
    #[error("runtime backend '{backend}' unavailable: {reason}")]
    BackendUnavailable {
        /// Configured backend name.
        backend: &'static str,
        /// Human-readable reason.
        reason: &'static str,
    },
}

/// Declarative spawn request consumed by [`ContainerRuntime::spawn`].
///
/// Each field is platform-agnostic and gets translated into the
/// backend's native vocabulary inside the runtime impl.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpawnSpec {
    /// Container image to launch (e.g. `"ubuntu:24.04"`). Required —
    /// an empty string is rejected by [`SpawnSpec::validate`].
    pub image: String,
    /// Optional name to assign to the container. Falls back to the
    /// backend's auto-generated name when `None`.
    pub name: Option<String>,
    /// Persona id label (`emberlink.persona_id`). Empty string means
    /// "not associated with a specific persona".
    pub persona_id: String,
    /// Agent UUID label (`emberlink.agent_uuid`).
    pub agent_uuid: String,
    /// Task id label (`emberlink.task_id`).
    pub task_id: String,
    /// Additional caller-supplied labels. Merged into the final label
    /// set AFTER the canonical `emberlink.*` labels so caller labels
    /// cannot shadow the canonical ones.
    pub labels: HashMap<String, String>,
    /// Environment variables (`KEY=VALUE` form, matching the Docker
    /// engine wire format).
    pub env: Vec<String>,
    /// Override the image entrypoint. `None` leaves the image default.
    pub entrypoint: Option<Vec<String>>,
    /// Command/args to run. `None` falls back to the image default.
    pub cmd: Option<Vec<String>>,
    /// Per-agent UDS sockets to bind-mount into the container.
    pub uds_mounts: Vec<UdsBindMount>,
}

/// One UDS socket bind-mount entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdsBindMount {
    /// Host-side path of the socket (or parent dir) being mounted in.
    pub host_path: PathBuf,
    /// Path inside the container where the socket (or parent dir)
    /// should appear.
    pub container_path: PathBuf,
    /// Read-only posture. `true` produces a read-only bind-mount.
    pub read_only: bool,
}

impl SpawnSpec {
    /// Validate the spec before any backend roundtrip.
    pub fn validate(&self) -> Result<(), RuntimeSpawnError> {
        if self.image.trim().is_empty() {
            return Err(RuntimeSpawnError::InvalidSpec(
                "image must be non-empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Compose the final label map: caller labels first, canonical
    /// daemon labels last so canonical keys cannot be shadowed.
    pub fn final_labels(&self) -> HashMap<String, String> {
        let mut out: HashMap<String, String> = self.labels.clone();
        out.insert("emberlink.persona_id".to_string(), self.persona_id.clone());
        out.insert("emberlink.agent_uuid".to_string(), self.agent_uuid.clone());
        out.insert("emberlink.task_id".to_string(), self.task_id.clone());
        out.insert("emberlink.created_at".to_string(), Utc::now().to_rfc3339());
        out
    }
}

#[derive(Debug)]
struct ConfiguredRuntime {
    backend: RuntimeBackend,
}

impl ConfiguredRuntime {
    fn unavailable<T>(&self) -> Result<T, RuntimeSpawnError> {
        Err(RuntimeSpawnError::BackendUnavailable {
            backend: self.backend.as_str(),
            reason: "no concrete daemon-side container runtime adapter is linked in this build",
        })
    }
}

#[async_trait]
impl ContainerRuntime for ConfiguredRuntime {
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError> {
        spec.validate()?;
        self.unavailable()
    }

    async fn bind_mount_uds(
        &self,
        _container_id: &str,
        _host_path: &Path,
        _in_container_path: &Path,
    ) -> Result<(), RuntimeSpawnError> {
        self.unavailable()
    }

    async fn drain(&self, _container_id: &str, _grace: Duration) -> Result<(), RuntimeSpawnError> {
        self.unavailable()
    }

    async fn state_report(&self, _container_id: &str) -> Result<RuntimeState, RuntimeSpawnError> {
        self.unavailable()
    }
}

/// Handle returned by a successful [`ContainerRuntime::spawn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnedContainer {
    /// Backend-assigned container id.
    pub container_id: String,
    /// Final name the backend assigned.
    pub name: Option<String>,
}

/// High-level lifecycle state observed by
/// [`ContainerRuntime::state_report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// The container is alive: created or running.
    Running,
    /// A lifecycle transition is in flight.
    Draining,
    /// The container is terminal or missing.
    Dead,
}

/// Cross-backend container-runtime contract.
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    /// Spawn a container as described by `spec` and return a handle.
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError>;

    /// Add or refresh a per-agent UDS bind-mount for a live container.
    ///
    /// Backends that cannot mutate mounts after create time should
    /// return [`RuntimeSpawnError::UnsupportedOperation`].
    async fn bind_mount_uds(
        &self,
        _container_id: &str,
        _host_path: &Path,
        _in_container_path: &Path,
    ) -> Result<(), RuntimeSpawnError> {
        Err(RuntimeSpawnError::UnsupportedOperation {
            operation: "bind_mount_uds",
        })
    }

    /// Stop the container identified by `container_id`, giving the
    /// entrypoint up to `grace` to exit gracefully before escalation.
    async fn drain(&self, container_id: &str, grace: Duration) -> Result<(), RuntimeSpawnError>;

    /// Inspect the container and report its reconciler-facing state.
    async fn state_report(&self, container_id: &str) -> Result<RuntimeState, RuntimeSpawnError>;
}

#[async_trait]
impl<T> ContainerRuntime for Box<T>
where
    T: ContainerRuntime + ?Sized,
{
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError> {
        (**self).spawn(spec).await
    }

    async fn bind_mount_uds(
        &self,
        container_id: &str,
        host_path: &Path,
        in_container_path: &Path,
    ) -> Result<(), RuntimeSpawnError> {
        (**self)
            .bind_mount_uds(container_id, host_path, in_container_path)
            .await
    }

    async fn drain(&self, container_id: &str, grace: Duration) -> Result<(), RuntimeSpawnError> {
        (**self).drain(container_id, grace).await
    }

    async fn state_report(&self, container_id: &str) -> Result<RuntimeState, RuntimeSpawnError> {
        (**self).state_report(container_id).await
    }
}

#[async_trait]
impl<T> ContainerRuntime for Arc<T>
where
    T: ContainerRuntime + ?Sized,
{
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError> {
        (**self).spawn(spec).await
    }

    async fn bind_mount_uds(
        &self,
        container_id: &str,
        host_path: &Path,
        in_container_path: &Path,
    ) -> Result<(), RuntimeSpawnError> {
        (**self)
            .bind_mount_uds(container_id, host_path, in_container_path)
            .await
    }

    async fn drain(&self, container_id: &str, grace: Duration) -> Result<(), RuntimeSpawnError> {
        (**self).drain(container_id, grace).await
    }

    async fn state_report(&self, container_id: &str) -> Result<RuntimeState, RuntimeSpawnError> {
        (**self).state_report(container_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_backend_parse_accepts_supported_values() {
        assert_eq!(
            RuntimeBackend::parse_config_value("docker-engine").unwrap(),
            RuntimeBackend::DockerEngine
        );
        assert_eq!(
            RuntimeBackend::parse_config_value("apple-container").unwrap(),
            RuntimeBackend::AppleContainer
        );
        assert_eq!(
            RuntimeBackend::parse_config_value("none-host-resident").unwrap(),
            RuntimeBackend::NoneHostResident
        );
    }

    #[test]
    fn runtime_backend_parse_rejects_unknown_with_supported_values() {
        let err = RuntimeBackend::parse_config_value("podman").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("podman"));
        for value in RuntimeBackend::supported_values() {
            assert!(msg.contains(value));
        }
    }

    #[tokio::test]
    async fn configured_runtime_fails_closed_until_backend_adapter_lands() {
        let runtime = RuntimeBackend::DockerEngine.resolve();
        let err = runtime
            .spawn(SpawnSpec {
                image: "ubuntu:24.04".to_string(),
                ..Default::default()
            })
            .await
            .expect_err("placeholder backend must fail closed");
        assert!(matches!(
            err,
            RuntimeSpawnError::BackendUnavailable {
                backend: "docker-engine",
                ..
            }
        ));
    }
}
