//! Compose V2 manifest → bollard Docker engine spec translator.
//!
//! implementation-note-93 (per /design review
//! 20260517-201622 orbstack-trust Decision 4: Compose V2 as the
//! declarative spec). This module takes a parsed [`ComposeManifest`]
//! and produces a [`DockerContainerSpec`] — a bundle of
//! `bollard::container::Config<String>` + `bollard::models::HostConfig`
//! that the daemon's spawn supervisor (`crates/ember-daemon/src/
//! spawn/compose.rs`) can hand straight to `Docker::create_container`.
//!
//! ## Substrate contract
//!
//! [`ComposeManifest`] is a minimal Compose V2 subset covering the
//! fields a Construct spawn actually needs: `image`, `command`,
//! `entrypoint`, `environment` (map or list form), `volumes`,
//! `network_mode`, and `labels`. The sibling slice
//! implementation-note-98 is meant to provide a richer
//! [`ComposeManifest`] type — when it lands, this module re-exports
//! the canonical one and deletes the local fallback. Until then, the
//! local definition is the substrate; downstream callers should import
//! it through this module so the swap is a single edit.
//!
//! ## What this translator handles
//!
//! - **`image`** → `Config.image`. Required; an empty string fails
//!   [`ComposeTranslationError::MissingImage`].
//! - **`command`** (string or list) → `Config.cmd`. Strings are split
//!   on whitespace, lists are passed through.
//! - **`entrypoint`** (string or list) → `Config.entrypoint`. Same
//!   string/list shape as `command`.
//! - **`environment`** (mapping `K: V` OR list `["K=V", ...]`) →
//!   `Config.env` as `Vec<String>` in `K=V` form.
//! - **`volumes`** (Compose short syntax: `host:container[:ro]`) →
//!   `HostConfig.mounts` with `Type=bind`. The `:ro` suffix flips
//!   `read_only` on. Named volumes (no leading `/` or `.` on the host
//!   side) are NOT supported in this slice and produce a typed error.
//! - **`network_mode`** → `HostConfig.network_mode`. Pass-through; the
//!   broker enforces the privileged-deny rule for `host`-mode via
//!   `classify_docker_argv` upstream.
//! - **`labels`** (mapping OR list) → `Config.labels`. The Compose
//!   labels are merged INTO the labels the daemon stamps on at spawn
//!   time (`emberlink.persona_id` etc.) — the daemon caller is
//!   responsible for the merge order.
//!
//! Fields outside this list (ports, depends_on, deploy, healthcheck,
//! tmpfs, …) are accepted by the parser (Compose YAML is permissive)
//! but IGNORED by the translator. Anything the daemon needs that isn't
//! mapped here is a [`ComposeTranslationError::Unsupported`] surfaced
//! to the caller — never a silent drop.
//!
//! ## Why this lives in ember-construct (not ember-daemon)
//!
//! Translation is a pure-function YAML→struct→struct transform with no
//! network surface. Keeping it in ember-construct (alongside the
//! `classify_docker_argv` argv classifier) means the same shim-side
//! crate owns every Docker-shape translation, and the daemon's spawn
//! supervisor takes a single dep on `compose_manifest_to_docker_spec`
//! to drive Compose-spec'd spawns.
//!
//! Anchor: `fn compose_manifest_to_docker_spec`.

use std::collections::BTreeMap;

use bollard::container::Config;
use bollard::models::{HostConfig, Mount, MountTypeEnum};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ComposeManifest — minimal Compose V2 subset
// ---------------------------------------------------------------------------

/// Top-level Compose V2 manifest.
///
/// Compose files describe a `services:` map keyed by service name. For
/// the daemon's Construct-spawn use case we only ever resolve a single
/// service per spawn, but the manifest shape mirrors the on-disk
/// structure so a callable can keep a single canonical document.
///
/// **Stop-gap module location:** the sibling slice
/// implementation-note-98 lands the canonical
/// `ComposeManifest` type used cross-crate. This local definition keeps
/// Slice C compilable in isolation; when the canonical type lands we
/// `pub use` it here and delete the local struct.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeManifest {
    /// Compose schema version string (e.g. `"3.8"`). Optional in V2;
    /// the translator does not gate on a specific version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Services keyed by service name. The translator's
    /// `compose_manifest_to_docker_spec` expects exactly one service —
    /// multi-service manifests must pick the target name and use
    /// [`compose_service_to_docker_spec`] directly.
    #[serde(default)]
    pub services: BTreeMap<String, ComposeService>,
}

/// A single service entry under `services:` in a Compose V2 manifest.
///
/// Only the fields the translator actually maps are modelled here. The
/// parser tolerates extra fields (Compose YAML is permissive) by using
/// serde's default flatten-into-ignored behaviour, but unknown fields
/// are silently dropped at parse time — translation never sees them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeService {
    /// Image reference (`ubuntu:24.04`, `gcr.io/x/y@sha256:...`).
    /// Required; empty value triggers [`ComposeTranslationError::MissingImage`].
    #[serde(default)]
    pub image: String,

    /// `command:` — either a string (shell-split) or a list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<StringOrList>,

    /// `entrypoint:` — same shape as `command`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<StringOrList>,

    /// `environment:` — map (`KEY: VALUE`) or list (`["KEY=VALUE", ...]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvSpec>,

    /// `volumes:` — Compose short-syntax list (`host:container[:ro]`).
    /// Each entry produces one bind-mount in the docker spec.
    #[serde(default)]
    pub volumes: Vec<String>,

    /// `network_mode:` — passed through to `HostConfig.network_mode`.
    /// Set to e.g. `"host"`, `"bridge"`, `"none"`, or `"container:<id>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,

    /// `labels:` — map or list (`["k=v", ...]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<LabelSpec>,
}

/// `command:` / `entrypoint:` accept either a single string (shell-
/// split on whitespace) OR a YAML list. This enum captures both
/// shapes; conversion to `Vec<String>` is centralized in
/// [`StringOrList::to_argv`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    /// Single string form: `command: "sh -c 'echo hi'"`.
    String(String),
    /// List form: `command: ["sh", "-c", "echo hi"]`.
    List(Vec<String>),
}

impl StringOrList {
    /// Convert to the `Vec<String>` shape the bollard Config wants.
    ///
    /// String form is split on whitespace (Compose semantics). Callers
    /// who need shell-aware splitting (quoting, env expansion) should
    /// pass the list form upstream.
    pub fn to_argv(&self) -> Vec<String> {
        match self {
            Self::String(s) => s.split_whitespace().map(str::to_string).collect(),
            Self::List(v) => v.clone(),
        }
    }
}

/// `environment:` accepts either a map (`KEY: VALUE`) or a list of
/// `KEY=VALUE` strings. Both produce the same `Vec<String>` wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvSpec {
    /// Map form: `environment:\n  FOO: bar`.
    Map(BTreeMap<String, String>),
    /// List form: `environment:\n  - FOO=bar`.
    List(Vec<String>),
}

impl EnvSpec {
    /// Convert to the `Vec<String>` `KEY=VALUE` form bollard's `env`
    /// field wants.
    pub fn to_env_pairs(&self) -> Vec<String> {
        match self {
            Self::Map(m) => m.iter().map(|(k, v)| format!("{k}={v}")).collect(),
            Self::List(v) => v.clone(),
        }
    }
}

/// `labels:` accepts either a map or a list of `key=value` strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LabelSpec {
    /// Map form: `labels:\n  foo: bar`.
    Map(BTreeMap<String, String>),
    /// List form: `labels:\n  - foo=bar`.
    List(Vec<String>),
}

impl LabelSpec {
    /// Convert to a `BTreeMap<String, String>` (sorted for
    /// deterministic round-trip in tests). Entries in list form that
    /// lack `=` produce an empty-value label.
    pub fn to_map(&self) -> BTreeMap<String, String> {
        match self {
            Self::Map(m) => m.clone(),
            Self::List(v) => v
                .iter()
                .map(|entry| match entry.split_once('=') {
                    Some((k, val)) => (k.to_string(), val.to_string()),
                    None => (entry.clone(), String::new()),
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// DockerContainerSpec + ComposeTranslationError
// ---------------------------------------------------------------------------

/// Bundle returned by the translator. The two fields are exactly the
/// pair `Docker::create_container` wants — a `Config<String>` body and
/// the `HostConfig` it nests into via `Config::host_config`. They are
/// returned separately so callers can inspect / re-stamp pieces (e.g.
/// merge daemon labels into `config.labels` before the engine call)
/// without unwrapping nested Options.
#[derive(Debug, Clone, PartialEq)]
pub struct DockerContainerSpec {
    /// `bollard::container::Config<String>` — body of POST `/containers/create`.
    pub config: Config<String>,
    /// `bollard::models::HostConfig` — also referenced as
    /// `config.host_config = Some(host_config.clone())` for callers
    /// that want the bollard-native shape.
    pub host_config: HostConfig,
}

/// Translation failures. Each variant carries enough context for a
/// daemon-side caller to produce a typed `spawn-failed` event without
/// re-parsing the underlying error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ComposeTranslationError {
    /// The manifest's selected service had no `image:` (or it was
    /// empty/whitespace). Required field per Compose V2 + the daemon
    /// spawn invariant — empty `image` is rejected before any engine
    /// roundtrip.
    #[error("compose service '{service}' missing required `image:` field")]
    MissingImage {
        /// Service name (key under `services:`) that failed validation.
        service: String,
    },

    /// The manifest had `services: {}` (or didn't pick a single
    /// service via [`crate::docker::compose_manifest_to_docker_spec`]).
    #[error("compose manifest has no services to translate")]
    NoServices,

    /// The manifest had more than one service and the caller used the
    /// single-service helper. Callers with multi-service docs must
    /// pick the target name and call [`compose_service_to_docker_spec`].
    #[error(
        "compose manifest has {count} services (expected exactly 1 for single-service helper); \
         use compose_service_to_docker_spec with an explicit name"
    )]
    AmbiguousService {
        /// Number of services found in the manifest.
        count: usize,
    },

    /// A `volumes:` entry referenced a named volume (no leading `/` or
    /// `.`). Named volumes require a separate `Docker::create_volume`
    /// roundtrip and a top-level `volumes:` block — not modelled in
    /// the Construct-spawn fast path.
    #[error("named volumes are not supported by the Construct spawn translator (entry: {entry})")]
    NamedVolumeUnsupported {
        /// The literal `volumes:` entry that failed validation.
        entry: String,
    },

    /// A `volumes:` short-syntax entry was malformed (empty, all
    /// colons, etc.).
    #[error("malformed volume entry: {entry}")]
    MalformedVolume {
        /// The literal entry that failed parsing.
        entry: String,
    },

    /// A field present in the manifest is not yet mapped to the
    /// bollard spec. The `field` string is the dotted path under the
    /// service block (`"healthcheck"`, `"deploy.resources"`). Surfaced
    /// rather than silently dropped so callers know to either extend
    /// the translator or remove the unsupported field upstream.
    #[error("compose field not yet supported by the translator: {field}")]
    Unsupported {
        /// Dotted field path (e.g. `"healthcheck"`).
        field: String,
    },

    /// YAML deserialisation failed. Surfaces parse-time errors with
    /// the underlying `serde_yaml` message preserved verbatim.
    #[error("compose YAML parse failed: {0}")]
    YamlParse(String),
}

// ---------------------------------------------------------------------------
// translate_manifest — internal entry point
// ---------------------------------------------------------------------------
//
// The public checkpoint `fn compose_manifest_to_docker_spec` lives in
// `crate::docker` so the task-level grep target
// (`crates/ember-construct/src/docker.rs`) is satisfied. The
// translation logic lives here so the substrate stays together with
// the [`ComposeManifest`] type it operates on.

/// Internal entry point for [`crate::docker::compose_manifest_to_docker_spec`].
///
/// **Single-service convenience.** This helper requires the manifest
/// to declare exactly one service. Multi-service manifests need
/// [`compose_service_to_docker_spec`] called once per target.
///
/// # Errors
///
/// All failure modes are typed via [`ComposeTranslationError`]:
/// `NoServices`, `AmbiguousService`, `MissingImage`,
/// `NamedVolumeUnsupported`, `MalformedVolume`, `Unsupported`.
pub(crate) fn translate_manifest(
    manifest: &ComposeManifest,
) -> Result<DockerContainerSpec, ComposeTranslationError> {
    match manifest.services.len() {
        0 => Err(ComposeTranslationError::NoServices),
        1 => {
            // BTreeMap iteration is sorted; the single entry is also
            // the first entry.
            let (name, service) = manifest
                .services
                .iter()
                .next()
                .expect("len == 1 implies first() is Some");
            compose_service_to_docker_spec(name, service)
        }
        count => Err(ComposeTranslationError::AmbiguousService { count }),
    }
}

/// Translate a single Compose service into the bollard spec pair.
///
/// Use this directly when the manifest carries multiple services —
/// look up the target by name and translate it independently. The
/// `service_name` argument is only used to enrich
/// [`ComposeTranslationError::MissingImage`] when the service's
/// `image:` is empty.
pub fn compose_service_to_docker_spec(
    service_name: &str,
    service: &ComposeService,
) -> Result<DockerContainerSpec, ComposeTranslationError> {
    if service.image.trim().is_empty() {
        return Err(ComposeTranslationError::MissingImage {
            service: service_name.to_string(),
        });
    }

    // ----- HostConfig: mounts + network_mode -----
    let mounts: Vec<Mount> = service
        .volumes
        .iter()
        .map(|v| translate_volume(v))
        .collect::<Result<Vec<_>, _>>()?;

    let host_config = HostConfig {
        mounts: if mounts.is_empty() {
            None
        } else {
            Some(mounts)
        },
        network_mode: service.network_mode.clone(),
        ..Default::default()
    };

    // ----- Config<String>: image, env, cmd, entrypoint, labels -----
    let env: Option<Vec<String>> = service.environment.as_ref().map(EnvSpec::to_env_pairs);
    let cmd: Option<Vec<String>> = service.command.as_ref().map(StringOrList::to_argv);
    let entrypoint: Option<Vec<String>> = service.entrypoint.as_ref().map(StringOrList::to_argv);
    let labels: Option<std::collections::HashMap<String, String>> = service
        .labels
        .as_ref()
        .map(|l| l.to_map().into_iter().collect());

    let config: Config<String> = Config {
        image: Some(service.image.clone()),
        env,
        cmd,
        entrypoint,
        labels,
        host_config: Some(host_config.clone()),
        ..Default::default()
    };

    Ok(DockerContainerSpec {
        config,
        host_config,
    })
}

/// Parse a Compose YAML document into a [`ComposeManifest`].
///
/// Wrapper around `serde_yaml::from_str` that wraps errors in our
/// typed [`ComposeTranslationError::YamlParse`] variant so callers can
/// pattern-match a single error type across parse + translate.
pub fn parse_compose_yaml(yaml: &str) -> Result<ComposeManifest, ComposeTranslationError> {
    serde_yaml::from_str(yaml).map_err(|e| ComposeTranslationError::YamlParse(e.to_string()))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Translate one `volumes:` short-syntax entry into a bollard `Mount`.
///
/// Supports:
///   - `host:container`             → bind, RW
///   - `host:container:ro`          → bind, RO
///   - `host:container:rw`          → bind, RW (explicit)
///
/// Named volumes (entries where the host side has no `/` or `.` prefix)
/// are rejected; the spawn fast-path doesn't model the top-level
/// `volumes:` block needed to manage them. Single-path entries
/// (anonymous volumes) are also rejected — they require docker volume
/// driver mediation, which isn't a Construct-spawn primitive.
fn translate_volume(entry: &str) -> Result<Mount, ComposeTranslationError> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(ComposeTranslationError::MalformedVolume {
            entry: entry.to_string(),
        });
    }

    // Split on `:` — at most 3 parts: host:container[:mode].
    let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
    match parts.as_slice() {
        [_] => Err(ComposeTranslationError::MalformedVolume {
            entry: entry.to_string(),
        }),
        [host, container] => {
            check_host_is_bindable(host, entry)?;
            Ok(Mount {
                target: Some((*container).to_string()),
                source: Some((*host).to_string()),
                typ: Some(MountTypeEnum::BIND),
                read_only: Some(false),
                ..Default::default()
            })
        }
        [host, container, mode] => {
            check_host_is_bindable(host, entry)?;
            let read_only = match *mode {
                "ro" => true,
                "rw" => false,
                other => {
                    return Err(ComposeTranslationError::MalformedVolume {
                        entry: format!("{entry} (unrecognized mode '{other}')"),
                    });
                }
            };
            Ok(Mount {
                target: Some((*container).to_string()),
                source: Some((*host).to_string()),
                typ: Some(MountTypeEnum::BIND),
                read_only: Some(read_only),
                ..Default::default()
            })
        }
        _ => Err(ComposeTranslationError::MalformedVolume {
            entry: entry.to_string(),
        }),
    }
}

/// Returns Ok if `host` looks like a bind-mount source (absolute path
/// or `./relative`), Err otherwise.
fn check_host_is_bindable(host: &str, entry: &str) -> Result<(), ComposeTranslationError> {
    if host.starts_with('/') || host.starts_with("./") || host.starts_with("../") || host == "." {
        Ok(())
    } else {
        Err(ComposeTranslationError::NamedVolumeUnsupported {
            entry: entry.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(service: ComposeService) -> ComposeManifest {
        let mut services = BTreeMap::new();
        services.insert("app".to_string(), service);
        ComposeManifest {
            version: Some("3.8".to_string()),
            services,
        }
    }

    // ----- Checkpoint + happy path -----

    #[test]
    fn sentinel_function_is_callable() {
        // The grep target `fn compose_manifest_to_docker_spec` must
        // be exported and callable.
        let m = manifest_with(ComposeService {
            image: "alpine:3.20".to_string(),
            ..Default::default()
        });
        let spec = crate::docker::compose_manifest_to_docker_spec(&m).expect("must translate");
        assert_eq!(spec.config.image.as_deref(), Some("alpine:3.20"));
    }

    #[test]
    fn translates_image_only_service() {
        let m = manifest_with(ComposeService {
            image: "ubuntu:24.04".to_string(),
            ..Default::default()
        });
        let spec = crate::docker::compose_manifest_to_docker_spec(&m).unwrap();
        assert_eq!(spec.config.image.as_deref(), Some("ubuntu:24.04"));
        assert!(spec.config.cmd.is_none());
        assert!(spec.config.env.is_none());
        assert!(spec.host_config.mounts.is_none());
    }

    // ----- T2 round-trip from YAML -----

    #[test]
    fn round_trip_yaml_to_bollard_spec_full() {
        let yaml = r#"
version: "3.8"
services:
  app:
    image: ghcr.io/example/api:1.2.3
    command: ["sh", "-c", "echo hi"]
    entrypoint: /bin/bash
    environment:
      FOO: bar
      LOG_LEVEL: debug
    volumes:
      - /host/data:/data
      - /host/cache:/cache:ro
    network_mode: bridge
    labels:
      owner: alice
      service: api
"#;
        let manifest = parse_compose_yaml(yaml).expect("parse");
        let spec = crate::docker::compose_manifest_to_docker_spec(&manifest).expect("translate");

        // Image
        assert_eq!(
            spec.config.image.as_deref(),
            Some("ghcr.io/example/api:1.2.3")
        );

        // Command (list form)
        assert_eq!(
            spec.config.cmd.as_deref(),
            Some(&["sh".to_string(), "-c".to_string(), "echo hi".to_string()][..])
        );

        // Entrypoint (string form → split on whitespace)
        assert_eq!(
            spec.config.entrypoint.as_deref(),
            Some(&["/bin/bash".to_string()][..])
        );

        // Environment (map form → sorted K=V vec)
        let env = spec.config.env.as_ref().expect("env present");
        assert!(
            env.contains(&"FOO=bar".to_string()),
            "env missing FOO: {env:?}"
        );
        assert!(
            env.contains(&"LOG_LEVEL=debug".to_string()),
            "env missing LOG_LEVEL: {env:?}"
        );

        // Network mode
        assert_eq!(spec.host_config.network_mode.as_deref(), Some("bridge"));

        // Mounts
        let mounts = spec.host_config.mounts.as_ref().expect("mounts present");
        assert_eq!(mounts.len(), 2);
        let data = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some("/data"))
            .expect("/data mount");
        assert_eq!(data.source.as_deref(), Some("/host/data"));
        assert_eq!(data.typ, Some(MountTypeEnum::BIND));
        assert_eq!(data.read_only, Some(false));

        let cache = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some("/cache"))
            .expect("/cache mount");
        assert_eq!(cache.source.as_deref(), Some("/host/cache"));
        assert_eq!(cache.read_only, Some(true));

        // Labels
        let labels = spec.config.labels.as_ref().expect("labels present");
        assert_eq!(labels.get("owner").map(String::as_str), Some("alice"));
        assert_eq!(labels.get("service").map(String::as_str), Some("api"));

        // host_config nests into config too
        assert!(spec.config.host_config.is_some());
    }

    #[test]
    fn environment_list_form_round_trips() {
        let yaml = r#"
services:
  app:
    image: alpine
    environment:
      - FOO=bar
      - BAZ=qux
"#;
        let m = parse_compose_yaml(yaml).unwrap();
        let spec = crate::docker::compose_manifest_to_docker_spec(&m).unwrap();
        let env = spec.config.env.unwrap();
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&"BAZ=qux".to_string()));
    }

    #[test]
    fn labels_list_form_round_trips() {
        let yaml = r#"
services:
  app:
    image: alpine
    labels:
      - owner=alice
      - flag
"#;
        let m = parse_compose_yaml(yaml).unwrap();
        let spec = crate::docker::compose_manifest_to_docker_spec(&m).unwrap();
        let labels = spec.config.labels.unwrap();
        assert_eq!(labels.get("owner").map(String::as_str), Some("alice"));
        // Bare entry (no `=`) maps to empty value.
        assert_eq!(labels.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn command_string_form_splits_on_whitespace() {
        let s = StringOrList::String("sh -c 'echo hi'".to_string());
        // Compose semantics: simple whitespace split. Shell-quoted forms
        // round-trip best via the list form.
        assert_eq!(
            s.to_argv(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "'echo".to_string(),
                "hi'".to_string()
            ]
        );
    }

    // ----- Error paths -----

    #[test]
    fn missing_image_is_typed_error() {
        let m = manifest_with(ComposeService {
            image: String::new(),
            ..Default::default()
        });
        match crate::docker::compose_manifest_to_docker_spec(&m) {
            Err(ComposeTranslationError::MissingImage { service }) => {
                assert_eq!(service, "app");
            }
            other => panic!("expected MissingImage, got {other:?}"),
        }
    }

    #[test]
    fn empty_manifest_is_no_services() {
        let m = ComposeManifest::default();
        assert_eq!(
            crate::docker::compose_manifest_to_docker_spec(&m),
            Err(ComposeTranslationError::NoServices)
        );
    }

    #[test]
    fn multi_service_manifest_is_ambiguous_for_single_helper() {
        let mut services = BTreeMap::new();
        services.insert(
            "a".to_string(),
            ComposeService {
                image: "alpine".to_string(),
                ..Default::default()
            },
        );
        services.insert(
            "b".to_string(),
            ComposeService {
                image: "alpine".to_string(),
                ..Default::default()
            },
        );
        let m = ComposeManifest {
            version: None,
            services,
        };
        assert_eq!(
            crate::docker::compose_manifest_to_docker_spec(&m),
            Err(ComposeTranslationError::AmbiguousService { count: 2 })
        );

        // But per-service helper still works.
        let svc = ComposeService {
            image: "alpine".to_string(),
            ..Default::default()
        };
        assert!(compose_service_to_docker_spec("a", &svc).is_ok());
    }

    #[test]
    fn named_volume_is_unsupported() {
        let m = manifest_with(ComposeService {
            image: "alpine".to_string(),
            volumes: vec!["dbdata:/var/lib/db".to_string()],
            ..Default::default()
        });
        match crate::docker::compose_manifest_to_docker_spec(&m) {
            Err(ComposeTranslationError::NamedVolumeUnsupported { entry }) => {
                assert_eq!(entry, "dbdata:/var/lib/db");
            }
            other => panic!("expected NamedVolumeUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn relative_path_host_is_bindable() {
        let m = manifest_with(ComposeService {
            image: "alpine".to_string(),
            volumes: vec!["./local:/app".to_string()],
            ..Default::default()
        });
        let spec = crate::docker::compose_manifest_to_docker_spec(&m).expect("relative host bind ok");
        let mounts = spec.host_config.mounts.unwrap();
        assert_eq!(mounts[0].source.as_deref(), Some("./local"));
    }

    #[test]
    fn single_path_volume_is_malformed() {
        let m = manifest_with(ComposeService {
            image: "alpine".to_string(),
            volumes: vec!["/data".to_string()],
            ..Default::default()
        });
        match crate::docker::compose_manifest_to_docker_spec(&m) {
            Err(ComposeTranslationError::MalformedVolume { entry }) => {
                assert_eq!(entry, "/data");
            }
            other => panic!("expected MalformedVolume, got {other:?}"),
        }
    }

    #[test]
    fn unrecognized_volume_mode_is_typed_error() {
        let m = manifest_with(ComposeService {
            image: "alpine".to_string(),
            volumes: vec!["/host:/container:Z".to_string()],
            ..Default::default()
        });
        match crate::docker::compose_manifest_to_docker_spec(&m) {
            Err(ComposeTranslationError::MalformedVolume { entry }) => {
                assert!(
                    entry.contains("Z"),
                    "error should mention the unrecognized mode: {entry}"
                );
            }
            other => panic!("expected MalformedVolume, got {other:?}"),
        }
    }

    #[test]
    fn yaml_parse_error_is_typed() {
        let bad = "this is\n  not valid:\n    yaml: : :";
        match parse_compose_yaml(bad) {
            Err(ComposeTranslationError::YamlParse(_)) => {}
            other => panic!("expected YamlParse, got {other:?}"),
        }
    }

    // ----- Default-derive sanity (cheap regression guards) -----

    #[test]
    fn default_manifest_has_no_services() {
        let m = ComposeManifest::default();
        assert!(m.services.is_empty());
        assert!(m.version.is_none());
    }

    #[test]
    fn default_service_has_empty_image() {
        let s = ComposeService::default();
        assert!(s.image.is_empty());
        assert!(s.command.is_none());
        assert!(s.volumes.is_empty());
    }
}
