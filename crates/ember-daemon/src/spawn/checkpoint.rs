//! CLASSIFICATION: PUBLIC
//!
//! Structured checkpoint events for the SCION agent spawn supervisor.
//!
//! Each stage of the spawn sequence — from `docker run` request through
//! orchestrator-agent readiness — emits exactly one [`SpawnCheckpointEvent`]
//! to the daemon event log (`.ember/engine/events.jsonl`).  A stall at any
//! stage is immediately distinguishable from a zero-progress hang.
//!
//! # Wire shape
//!
//! ```json
//! {
//!   "event": "spawn_checkpoint",
//!   "kind": "container_created",
//!   "container_id": "abc123",
//!   "agent_id": "<uuid>",
//!   "outcome": "ok",
//!   "ts": "2026-05-13T01:00:14Z"
//! }
//! ```
//!
//! On error the object additionally carries `"reason": "<human-readable text>"`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One step in the SCION agent spawn lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpawnCheckpoint {
    DockerRunRequested,
    ContainerCreated { container_id: String },
    SciontoolAlive,
    EmberExecReady,
    AnthropicBootstrapReady,
    OrchestratorAgentReady { persona_id: String },
}

/// Outcome attached to each checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SpawnCheckpointResult {
    Ok,
    Err { reason: String },
}

/// A fully-stamped checkpoint event ready for the daemon event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnCheckpointEvent {
    pub ts: DateTime<Utc>,
    pub agent_id: String,
    #[serde(flatten)]
    pub checkpoint: SpawnCheckpoint,
    #[serde(flatten)]
    pub result: SpawnCheckpointResult,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from [`emit_checkpoint`].
#[derive(Debug)]
pub enum CheckpointError {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "checkpoint I/O: {e}"),
            Self::Serde(e) => write!(f, "checkpoint serialization: {e}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

// ---------------------------------------------------------------------------
// Emit helper — path-injectable for testability
// ---------------------------------------------------------------------------

/// Append a checkpoint event to an arbitrary JSONL path.
///
/// This is the inner, path-injectable form used by tests.  Production callers
/// go through [`emit_checkpoint`] which resolves the daemon event-log path
/// automatically.
pub fn emit_checkpoint_to(
    path: &std::path::Path,
    agent_id: &str,
    checkpoint: SpawnCheckpoint,
    result: SpawnCheckpointResult,
) -> Result<(), CheckpointError> {
    use std::fs::OpenOptions;
    use std::io::Write as IoWrite;

    let event = SpawnCheckpointEvent {
        ts: Utc::now(),
        agent_id: agent_id.to_string(),
        checkpoint,
        result,
    };

    // Merge the event into a flat JSON object with the top-level "event" key.
    let mut obj = serde_json::to_value(&event).map_err(CheckpointError::Serde)?;
    let map = obj
        .as_object_mut()
        .expect("SpawnCheckpointEvent always serializes as a JSON object");
    // The autopilot event log expects an "event" discriminator field.
    map.insert("event".to_string(), serde_json::json!("spawn_checkpoint"));

    let line = serde_json::to_string(&obj).map_err(CheckpointError::Serde)?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(CheckpointError::Io)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(CheckpointError::Io)?;
    writeln!(f, "{line}").map_err(CheckpointError::Io)?;
    Ok(())
}

/// Emit a checkpoint event to the daemon event log.
///
/// Writes to `.ember/engine/events.jsonl` via the existing event-append path
/// in `internal-automation`.  The path is resolved relative to the primary git
/// worktree root, matching how all other autopilot events are written.
///
/// Errors are returned so the caller can decide whether a failed checkpoint
/// write should be fatal.  In the spawn supervisor the failure should be
/// logged as a warning, not a fatal error — the agent launch itself is
/// not blocked by observability writes.
pub async fn emit_checkpoint(
    agent_id: &str,
    checkpoint: SpawnCheckpoint,
    result: SpawnCheckpointResult,
) -> Result<(), CheckpointError> {
    // Resolve the primary worktree root + engine event-log path via the
    // shared layout contract (core-construct-runtime, below both daemon and
    // engine per ADR 183/184). Fall back to cwd on failure (daemon is
    // typically launched from the repo root; this is a best-effort path).
    let root = core_construct_runtime::layout::primary_worktree_root()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let events_path = root.join(core_construct_runtime::layout::ENGINE_EVENTS_FILE);
    emit_checkpoint_to(&events_path, agent_id, checkpoint, result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // T1: serde roundtrip — each SpawnCheckpoint variant
    // -----------------------------------------------------------------------

    fn roundtrip_checkpoint(c: SpawnCheckpoint) -> SpawnCheckpoint {
        let json = serde_json::to_string(&c).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn serde_roundtrip_each_checkpoint_variant() {
        let variants = vec![
            SpawnCheckpoint::DockerRunRequested,
            SpawnCheckpoint::ContainerCreated {
                container_id: "abc123def456".to_string(),
            },
            SpawnCheckpoint::SciontoolAlive,
            SpawnCheckpoint::EmberExecReady,
            SpawnCheckpoint::AnthropicBootstrapReady,
            SpawnCheckpoint::OrchestratorAgentReady {
                persona_id: "persona-00000000-0000-0000-0000-000000000001".to_string(),
            },
        ];

        for variant in variants {
            let rt = roundtrip_checkpoint(variant.clone());
            assert_eq!(variant, rt, "roundtrip mismatch for {:?}", variant);
        }
    }

    #[test]
    fn serde_roundtrip_result_ok_and_err() {
        let ok = SpawnCheckpointResult::Ok;
        let json_ok = serde_json::to_string(&ok).expect("serialize ok");
        let rt_ok: SpawnCheckpointResult = serde_json::from_str(&json_ok).expect("deserialize ok");
        assert_eq!(ok, rt_ok);

        let err = SpawnCheckpointResult::Err {
            reason: "mount failed: no such file".to_string(),
        };
        let json_err = serde_json::to_string(&err).expect("serialize err");
        let rt_err: SpawnCheckpointResult =
            serde_json::from_str(&json_err).expect("deserialize err");
        assert_eq!(err, rt_err);
    }

    // -----------------------------------------------------------------------
    // T1: the `kind` discriminator appears in the serialized JSON
    // -----------------------------------------------------------------------

    #[test]
    fn checkpoint_kind_tag_in_json() {
        let c = SpawnCheckpoint::DockerRunRequested;
        let json = serde_json::to_string(&c).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(
            v.get("kind").and_then(|k| k.as_str()),
            Some("docker_run_requested"),
        );

        let c2 = SpawnCheckpoint::ContainerCreated {
            container_id: "xyz".to_string(),
        };
        let json2 = serde_json::to_string(&c2).expect("serialize");
        let v2: serde_json::Value = serde_json::from_str(&json2).expect("parse");
        assert_eq!(
            v2.get("kind").and_then(|k| k.as_str()),
            Some("container_created"),
        );
        assert_eq!(v2.get("container_id").and_then(|v| v.as_str()), Some("xyz"),);
    }

    // -----------------------------------------------------------------------
    // T1: emit_checkpoint_to appends one line to a tempdir-backed file
    // -----------------------------------------------------------------------

    #[test]
    fn emit_checkpoint_appends_to_event_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("events.jsonl");

        emit_checkpoint_to(
            &log_path,
            "agent-test-001",
            SpawnCheckpoint::ContainerCreated {
                container_id: "container-abc".to_string(),
            },
            SpawnCheckpointResult::Ok,
        )
        .expect("emit ok");

        let contents = std::fs::read_to_string(&log_path).expect("read log");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1, "expected exactly one line");

        let v: serde_json::Value = serde_json::from_str(lines[0]).expect("parse line as JSON");

        assert_eq!(
            v.get("event").and_then(|e| e.as_str()),
            Some("spawn_checkpoint"),
            "event discriminator must be spawn_checkpoint"
        );
        assert_eq!(
            v.get("kind").and_then(|k| k.as_str()),
            Some("container_created"),
        );
        assert_eq!(
            v.get("container_id").and_then(|c| c.as_str()),
            Some("container-abc"),
        );
        assert_eq!(
            v.get("agent_id").and_then(|a| a.as_str()),
            Some("agent-test-001"),
        );
        assert_eq!(v.get("outcome").and_then(|o| o.as_str()), Some("ok"),);
        assert!(v.get("ts").is_some(), "ts must be present");
    }

    #[test]
    fn emit_checkpoint_appends_multiple_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("events.jsonl");

        emit_checkpoint_to(
            &log_path,
            "agent-test-002",
            SpawnCheckpoint::DockerRunRequested,
            SpawnCheckpointResult::Ok,
        )
        .expect("emit 1");

        emit_checkpoint_to(
            &log_path,
            "agent-test-002",
            SpawnCheckpoint::SciontoolAlive,
            SpawnCheckpointResult::Err {
                reason: "sciontool timed out".to_string(),
            },
        )
        .expect("emit 2");

        let contents = std::fs::read_to_string(&log_path).expect("read log");
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "expected two appended lines");

        let v1: serde_json::Value = serde_json::from_str(lines[0]).expect("parse line 1");
        assert_eq!(
            v1.get("kind").and_then(|k| k.as_str()),
            Some("docker_run_requested"),
        );

        let v2: serde_json::Value = serde_json::from_str(lines[1]).expect("parse line 2");
        assert_eq!(
            v2.get("kind").and_then(|k| k.as_str()),
            Some("sciontool_alive"),
        );
        assert_eq!(v2.get("outcome").and_then(|o| o.as_str()), Some("err"),);
        assert_eq!(
            v2.get("reason").and_then(|r| r.as_str()),
            Some("sciontool timed out"),
        );
    }
}
