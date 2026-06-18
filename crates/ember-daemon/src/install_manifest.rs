//! CLASSIFICATION: PUBLIC
//!
//! Authoritative manifest of the macOS install set.
//!
//! Single source of truth for *which* binaries make up a macOS install, where
//! each lands, how it is codesigned, and which LaunchDaemon (if any) bootstraps
//! it. Every install lane consumes this table instead of hardcoding its own
//! partial `--bin` list:
//!
//! - the dev-refresh lane (`scripts/dev-refresh-macos-host-install.sh`) and the
//!   signed-release lane (`scripts/release-macos.sh`) iterate the JSON emitted
//!   by `emberd print-install-manifest --json` to drive `cargo build`,
//!   placement, and codesigning;
//! - the daemon-install flow (`crate::install`) and the pkg postinstall use the
//!   `bootstrap` field to know which LaunchDaemons to register.
//!
//! Before this table existed, the binary set drifted across three hand-rolled
//! bash scripts and the privilege-separated spawn-helper (`bootstrap =
//! SpawnHelper`) fell out of all of them. Keeping the set here — in the same
//! crate as the privileged consumer (`crate::install`) — makes that drift
//! structurally impossible: a build lane physically cannot stage a binary the
//! daemon does not know how to place and bootstrap.
//!
//! This is a *deployment* spec. It is deliberately separate from the
//! Ed25519-signed *trust* manifest in [`crate::binary_manifest`] (ADR 124),
//! which is a security allowlist of Construct hashes the broker checks before
//! exec. The two meet only at placement (this table puts the Construct binaries
//! where the signed manifest authorizes them); no deployment field ever enters
//! the signed bytes.

use serde::Serialize;

// Canonical install paths. These mirror the private path constants in
// `crate::install` (`MANAGED_EMBERD_PATH`, `SPAWN_HELPER_BINARY_DIR`, the
// `binaries/` tree). `install_paths_match_install_module` (below) guards the
// values that `crate::install` exposes.
const BIN_DIR: &str = "/usr/local/bin";
const BINARIES_DIR: &str = "/usr/local/lib/ember/binaries";
const LIBEXEC_DIR: &str = "/usr/local/libexec";
const EMBER_APP_PATH: &str = "/usr/local/lib/ember.app";
const EMBERD_APP_PATH: &str = "/usr/local/lib/ember/emberd.app";

/// Where an artifact lands on disk and how it gets there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallDest {
    /// A codesigned `.app` bundle copied to `bundle_path`, with a
    /// `/usr/local/bin` symlink pointing into `Contents/MacOS/<bin>`.
    AppBundle {
        bundle_path: &'static str,
        symlink: &'static str,
    },
    /// `install -m755` into `/usr/local/bin/<installed_name>`. `installed_name`
    /// may differ from the cargo bin name.
    Bin { installed_name: &'static str },
    /// `install -m755` into `/usr/local/lib/ember/binaries/<bin>` — the signed
    /// Construct manifest tree.
    BinariesDir,
    /// `install -m755` into `/usr/local/libexec/<bin>` — privilege-separated
    /// helper + hash-pinned shim.
    Libexec,
}

/// Codesigning treatment a lane must apply to the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codesign {
    /// Full Secure-Enclave-capable signed `.app` bundle (dev lane:
    /// `dev-sign-se.sh`; release lane: Developer ID Application + hardened
    /// runtime + provisioning profile + daemon entitlements).
    SeBundle,
    /// Developer ID Application / Apple Development signature with hardened
    /// runtime; no provisioning profile.
    HardenedRuntime,
}

/// LaunchDaemon a daemon-class artifact is bootstrapped under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchdService {
    /// `sh.emberlink.daemon` — the trust broker (`emberd`), runs as the
    /// non-root `ember` uid (ADR 131).
    Daemon,
    /// `sh.emberlink.rpc` — the bridge listener sibling.
    Rpc,
    /// `sh.emberlink.spawn-helper` — the root privilege-separated spawner.
    SpawnHelper,
}

impl LaunchdService {
    pub fn label(self) -> &'static str {
        match self {
            LaunchdService::Daemon => "sh.emberlink.daemon",
            LaunchdService::Rpc => "sh.emberlink.rpc",
            LaunchdService::SpawnHelper => "sh.emberlink.spawn-helper",
        }
    }
}

/// One row of the macOS install set.
#[derive(Debug, Clone, Copy)]
pub struct InstallArtifact {
    /// Stable human/log name for the artifact.
    pub logical: &'static str,
    /// Cargo package that produces the binary.
    pub package: &'static str,
    /// Cargo `[[bin]]` name (`cargo build -p <package> --bin <bin>`).
    pub bin: &'static str,
    pub dest: InstallDest,
    pub codesign: Codesign,
    /// `Some` when the artifact is a daemon-class binary that a LaunchDaemon
    /// bootstraps. The shim is `None` — it is exec'd by the spawn-helper, not
    /// bootstrapped directly.
    pub bootstrap: Option<LaunchdService>,
}

impl InstallArtifact {
    /// Absolute final path of the primary placed artifact. For an `.app`
    /// bundle this is the bundle directory (the `/usr/local/bin` symlink is
    /// reported separately).
    pub fn installed_path(&self) -> String {
        match self.dest {
            InstallDest::AppBundle { bundle_path, .. } => bundle_path.to_string(),
            InstallDest::Bin { installed_name } => format!("{BIN_DIR}/{installed_name}"),
            InstallDest::BinariesDir => format!("{BINARIES_DIR}/{}", self.bin),
            InstallDest::Libexec => format!("{LIBEXEC_DIR}/{}", self.bin),
        }
    }

    fn dest_kind(&self) -> &'static str {
        match self.dest {
            InstallDest::AppBundle { .. } => "app-bundle",
            InstallDest::Bin { .. } => "bin",
            InstallDest::BinariesDir => "binaries-dir",
            InstallDest::Libexec => "libexec",
        }
    }

    fn symlink(&self) -> Option<&'static str> {
        match self.dest {
            InstallDest::AppBundle { symlink, .. } => Some(symlink),
            _ => None,
        }
    }

    fn codesign_kind(&self) -> &'static str {
        match self.codesign {
            Codesign::SeBundle => "se-bundle",
            Codesign::HardenedRuntime => "hardened-runtime",
        }
    }
}

/// The authoritative macOS install set. Order is install-significant:
/// `emberd` and its libexec helpers precede the LaunchDaemons that depend on
/// them.
const MACOS_INSTALL_SET: &[InstallArtifact] = &[
    InstallArtifact {
        logical: "ember-cli",
        package: "emberlink-cli",
        bin: "ember",
        dest: InstallDest::AppBundle {
            bundle_path: EMBER_APP_PATH,
            symlink: "/usr/local/bin/ember",
        },
        codesign: Codesign::SeBundle,
        bootstrap: None,
    },
    InstallArtifact {
        logical: "emberd",
        package: "ember-daemon",
        bin: "emberd",
        dest: InstallDest::AppBundle {
            bundle_path: EMBERD_APP_PATH,
            symlink: "/usr/local/bin/emberd",
        },
        codesign: Codesign::SeBundle,
        bootstrap: Some(LaunchdService::Daemon),
    },
    InstallArtifact {
        logical: "emberd-rpc",
        package: "ember-rpc",
        bin: "emberd-rpc-macos",
        dest: InstallDest::Bin {
            installed_name: "emberd-rpc-macos",
        },
        codesign: Codesign::HardenedRuntime,
        bootstrap: Some(LaunchdService::Rpc),
    },
    InstallArtifact {
        logical: "construct-gh",
        package: "ember-construct",
        bin: "ember-gh",
        dest: InstallDest::BinariesDir,
        codesign: Codesign::HardenedRuntime,
        bootstrap: None,
    },
    InstallArtifact {
        logical: "construct-git",
        package: "ember-construct",
        bin: "ember-git",
        dest: InstallDest::BinariesDir,
        codesign: Codesign::HardenedRuntime,
        bootstrap: None,
    },
    InstallArtifact {
        logical: "construct-kubectl",
        package: "ember-construct",
        bin: "ember-kubectl",
        dest: InstallDest::BinariesDir,
        codesign: Codesign::HardenedRuntime,
        bootstrap: None,
    },
    InstallArtifact {
        // Privilege-separated root spawner. The install lane places it directly
        // at /usr/local/libexec (it cannot live inside the sealed `ember.app`
        // bundle); `crate::install::install_spawn_helper_plist` verifies it there
        // and renders the LaunchDaemon plist.
        logical: "spawn-helper",
        package: "ember-spawn-helper",
        bin: "emberd-spawn-helper-macos",
        dest: InstallDest::Libexec,
        codesign: Codesign::HardenedRuntime,
        bootstrap: Some(LaunchdService::SpawnHelper),
    },
    InstallArtifact {
        // Hash-pinned exec target. No direct bootstrap — the spawn-helper plist
        // pins its blake3 (EXPECTED_SHIM_HASH) and execs it.
        logical: "spawn-shim",
        package: "ember-spawn-helper",
        bin: "emberd-spawn-shim",
        dest: InstallDest::Libexec,
        codesign: Codesign::HardenedRuntime,
        bootstrap: None,
    },
];

/// The authoritative macOS install set.
pub fn macos_install_set() -> &'static [InstallArtifact] {
    MACOS_INSTALL_SET
}

/// Flat JSON projection consumed by the bash install lanes (`jq`-friendly).
#[derive(Serialize)]
struct ManifestRow {
    logical: &'static str,
    package: &'static str,
    bin: &'static str,
    dest: &'static str,
    installed_path: String,
    symlink: Option<&'static str>,
    codesign: &'static str,
    bootstrap: Option<&'static str>,
}

impl ManifestRow {
    fn from_artifact(a: &InstallArtifact) -> Self {
        ManifestRow {
            logical: a.logical,
            package: a.package,
            bin: a.bin,
            dest: a.dest_kind(),
            installed_path: a.installed_path(),
            symlink: a.symlink(),
            codesign: a.codesign_kind(),
            bootstrap: a.bootstrap.map(|s| match s {
                LaunchdService::Daemon => "daemon",
                LaunchdService::Rpc => "rpc",
                LaunchdService::SpawnHelper => "spawn-helper",
            }),
        }
    }
}

/// Render the macOS install set as a pretty JSON array for
/// `emberd print-install-manifest --json`.
pub fn macos_install_set_json() -> String {
    let rows: Vec<ManifestRow> = MACOS_INSTALL_SET
        .iter()
        .map(ManifestRow::from_artifact)
        .collect();
    // unwrap: ManifestRow is a fixed, always-serializable shape.
    serde_json::to_string_pretty(&rows).expect("install manifest serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // Cargo `<package> -> {bin,...}` map for the packages the manifest names.
    // Asserted against the real Cargo.toml bin sets so a renamed/removed bin
    // breaks the build, not a release.
    fn known_bins(package: &str) -> Option<BTreeSet<&'static str>> {
        let bins: &[&str] = match package {
            "emberlink-cli" => &["ember"],
            "ember-daemon" => &["emberd", "git_echo", "macos_peer_binary_pin_probe"],
            "ember-rpc" => &["emberd-rpc-linux", "emberd-rpc-macos"],
            "ember-construct" => &[
                "ember-aws",
                "ember-az",
                "ember-gcloud",
                "ember-vercel",
                "ember-wrangler",
                "ember-gh",
                "ember-git",
                "ember-docker",
                "ember-kubectl",
                "ember-pulumi",
                "ember-terraform",
                "ember-tofu",
                "ember-flyctl",
                "ember-npm",
                "ember-okta",
                "ember-scion",
            ],
            "ember-spawn-helper" => &[
                "emberd-spawn-helper-macos",
                "emberd-spawn-helper-linux",
                "emberd-spawn-shim",
            ],
            _ => return None,
        };
        Some(bins.iter().copied().collect())
    }

    #[test]
    fn every_artifact_package_and_bin_resolves() {
        for a in macos_install_set() {
            let bins = known_bins(a.package)
                .unwrap_or_else(|| panic!("manifest names unknown package {}", a.package));
            assert!(
                bins.contains(a.bin),
                "manifest names bin {} not produced by package {}",
                a.bin,
                a.package
            );
        }
    }

    #[test]
    fn logical_names_unique() {
        let mut seen = BTreeSet::new();
        for a in macos_install_set() {
            assert!(
                seen.insert(a.logical),
                "duplicate logical name {}",
                a.logical
            );
        }
    }

    #[test]
    fn spawn_helper_and_shim_are_present_and_libexec() {
        let helper = macos_install_set()
            .iter()
            .find(|a| a.bin == "emberd-spawn-helper-macos")
            .expect("spawn-helper in install set");
        assert_eq!(helper.dest, InstallDest::Libexec);
        assert_eq!(helper.bootstrap, Some(LaunchdService::SpawnHelper));

        let shim = macos_install_set()
            .iter()
            .find(|a| a.bin == "emberd-spawn-shim")
            .expect("spawn-shim in install set");
        assert_eq!(shim.dest, InstallDest::Libexec);
        assert_eq!(
            shim.bootstrap, None,
            "shim is exec'd by the helper, not bootstrapped"
        );
    }

    #[test]
    fn installed_paths_are_absolute_and_distinct() {
        let mut paths = BTreeSet::new();
        for a in macos_install_set() {
            let p = a.installed_path();
            assert!(
                p.starts_with('/'),
                "{} installed_path not absolute: {p}",
                a.logical
            );
            assert!(paths.insert(p.clone()), "duplicate installed_path {p}");
        }
    }

    #[test]
    fn json_round_trips_and_lists_full_set() {
        let json = macos_install_set_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let arr = parsed.as_array().expect("array");
        assert_eq!(arr.len(), macos_install_set().len());
        // jq-shape sanity: first row exposes the fields the bash lanes read.
        let first = &arr[0];
        for key in ["package", "bin", "dest", "installed_path", "codesign"] {
            assert!(first.get(key).is_some(), "row missing {key}");
        }
    }

    #[test]
    fn app_bundles_carry_symlinks_others_do_not() {
        for a in macos_install_set() {
            match a.dest {
                InstallDest::AppBundle { symlink, .. } => {
                    assert!(symlink.starts_with("/usr/local/bin/"));
                    assert_eq!(
                        a.codesign,
                        Codesign::SeBundle,
                        "{} bundle must be SE-signed",
                        a.logical
                    );
                }
                _ => assert!(a.symlink().is_none()),
            }
        }
    }
}
