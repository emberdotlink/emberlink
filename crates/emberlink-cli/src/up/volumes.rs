//! CLASSIFICATION: PUBLIC
//!
//! per_agent_volume — per-agent-persona named volume helpers for build-artifact
//! caches (`target/`, `node_modules/`, `.venv/`, `.cargo/`).
//!
//! ADR 166 Component 4 §Volume mount policy: build-artifact caches are scoped
//! per-agent-persona and MUST NOT be shared across agents in a fleet. Cross-agent
//! cache reuse would let agent A poison `target/.../build-script-build` and
//! execute it as agent B on next build — defeating container isolation. Fleet-wide
//! cache acceleration is deferred to v0.3.1+ (requires content-addressed cache
//! primitives).
//!
//! Volume naming convention: `ember-build-<type>-<agent-id>` where `<agent-id>`
//! is the opaque identifier minted at agent-persona creation time.

use std::io;
use std::process::Command;

/// Named-volume identifiers for a single agent-persona's build-artifact caches.
///
/// Each field holds the Docker volume name that should be passed to
/// `docker volume create` and referenced in the Compose `volumes:` block.
pub struct PerAgentVolumes {
    /// Cargo registry + build cache: `ember-build-cargo-<agent-id>`
    pub cargo: String,
    /// Node.js module cache: `ember-build-node-modules-<agent-id>`
    pub node_modules: String,
    /// Python virtual-environment cache: `ember-build-venv-<agent-id>`
    pub venv: String,
}

/// Return the named-volume identifiers for the given agent-persona.
///
/// The returned names are stable: calling this function twice with the same
/// `agent_id` always returns the same volume names.  Two distinct `agent_id`
/// values always produce non-overlapping sets of names.
pub fn per_agent_volume_names(agent_id: &str) -> PerAgentVolumes {
    PerAgentVolumes {
        cargo: format!("ember-build-cargo-{agent_id}"),
        node_modules: format!("ember-build-node-modules-{agent_id}"),
        venv: format!("ember-build-venv-{agent_id}"),
    }
}

/// Remove the per-agent-persona build-artifact volumes for the listed agents.
///
/// Invokes `docker volume rm` once per volume.  Volumes that do not exist are
/// collected as warning strings rather than hard errors so that `ember down
/// --purge` can run idempotently against a fleet that was only partially
/// provisioned.
///
/// Returns `Ok(warnings)` where `warnings` is the list of volume names that
/// were not found (and therefore were not removed).  Returns `Err` only for
/// genuine I/O failures (e.g. `docker` not on PATH, permission denied).
pub fn purge_per_agent_volumes(agent_ids: &[&str]) -> io::Result<Vec<String>> {
    let mut warnings: Vec<String> = Vec::new();

    for &agent_id in agent_ids {
        let vols = per_agent_volume_names(agent_id);
        for vol_name in [vols.cargo, vols.node_modules, vols.venv] {
            let output = Command::new("docker")
                .args(["volume", "rm", &vol_name])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Docker exits non-zero with "No such volume" when the volume
                // does not exist.  Treat that as a warning, not an error.
                if stderr.contains("No such volume") {
                    warnings.push(vol_name);
                } else {
                    return Err(io::Error::other(format!(
                        "docker volume rm {vol_name} failed: {stderr}"
                    )));
                }
            }
        }
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naming_convention_cargo() {
        let vols = per_agent_volume_names("abc123");
        assert_eq!(vols.cargo, "ember-build-cargo-abc123");
    }

    #[test]
    fn naming_convention_node_modules() {
        let vols = per_agent_volume_names("abc123");
        assert_eq!(vols.node_modules, "ember-build-node-modules-abc123");
    }

    #[test]
    fn naming_convention_venv() {
        let vols = per_agent_volume_names("abc123");
        assert_eq!(vols.venv, "ember-build-venv-abc123");
    }

    #[test]
    fn different_agent_ids_produce_non_overlapping_volume_names() {
        let a = per_agent_volume_names("agent-alpha");
        let b = per_agent_volume_names("agent-beta");

        let a_names = [a.cargo.as_str(), a.node_modules.as_str(), a.venv.as_str()];
        let b_names = [b.cargo.as_str(), b.node_modules.as_str(), b.venv.as_str()];

        for a_name in &a_names {
            for b_name in &b_names {
                assert_ne!(
                    a_name, b_name,
                    "volume names must not overlap across agents: {a_name} == {b_name}"
                );
            }
        }
    }

    #[test]
    fn same_agent_id_produces_stable_names() {
        let first = per_agent_volume_names("stable-id");
        let second = per_agent_volume_names("stable-id");
        assert_eq!(first.cargo, second.cargo);
        assert_eq!(first.node_modules, second.node_modules);
        assert_eq!(first.venv, second.venv);
    }
}
