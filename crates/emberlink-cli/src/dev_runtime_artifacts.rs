//! Worktree-dev runtime artifact inventory.
//!
//! Hidden `ember dev ...` flows build and stage a fixed set of binaries into
//! the current worktree runtime. Keep the package->binary mapping here so
//! `ember dev install`, `ember dev sync`, and `ember dev info` stay aligned.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::dev_runtime::DevRuntimeEnv;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevRuntimeArtifactKind {
    Cli,
    Daemon,
    Construct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevRuntimeArtifact {
    pub package_name: &'static str,
    pub binary_name: String,
    pub kind: DevRuntimeArtifactKind,
}

impl DevRuntimeArtifact {
    pub fn new(
        package_name: &'static str,
        binary_name: impl Into<String>,
        kind: DevRuntimeArtifactKind,
    ) -> Self {
        Self {
            package_name,
            binary_name: binary_name.into(),
            kind,
        }
    }

    pub fn built_path(&self, workspace_root: &Path) -> PathBuf {
        workspace_root
            .join("target")
            .join("release")
            .join(&self.binary_name)
    }

    pub fn installed_path(&self, runtime: &DevRuntimeEnv) -> PathBuf {
        runtime.install_root.join(&self.binary_name)
    }
}

pub fn runtime_artifacts() -> Vec<DevRuntimeArtifact> {
    let mut artifacts = vec![
        DevRuntimeArtifact::new("emberlink-cli", "ember", DevRuntimeArtifactKind::Cli),
        DevRuntimeArtifact::new("ember-daemon", "emberd", DevRuntimeArtifactKind::Daemon),
    ];

    artifacts.extend(ember_construct::VENDORS.iter().map(|vendor| {
        DevRuntimeArtifact::new(
            "ember-construct",
            format!("ember-{}", vendor.name),
            DevRuntimeArtifactKind::Construct,
        )
    }));

    artifacts
}

pub fn build_packages() -> Vec<&'static str> {
    runtime_artifacts()
        .into_iter()
        .map(|artifact| artifact.package_name)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_packages_stay_deduped() {
        let packages = build_packages();
        let unique = packages.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(packages.len(), unique.len(), "packages must stay deduped");
    }

    #[test]
    fn artifact_inventory_includes_cli_daemon_and_constructs() {
        let artifacts = runtime_artifacts();
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.binary_name == "ember"),
            "dev runtime must include ember CLI"
        );
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.binary_name == "emberd"),
            "dev runtime must include daemon"
        );
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.binary_name == "ember-gh"
                    && artifact.kind == DevRuntimeArtifactKind::Construct),
            "dev runtime must include cohort-A construct binaries"
        );
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.binary_name == "ember-git"
                    && artifact.kind == DevRuntimeArtifactKind::Construct),
            "dev runtime must include git construct binaries"
        );
    }
}
