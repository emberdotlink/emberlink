"""Integration tests for the emberlink-agent Python SDK.

These tests spawn the real `emberlink-agent` binary over stdio and exercise
each protocol method end-to-end. They are skipped automatically when the
binary has not been built.

Build the binary first:
    cargo build -p emberlink-agent
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from emberlink_agent.client import EmberAgent, EmberAgentError
from emberlink_agent.types import AgentConfig

# Resolve binary relative to this file: packages/agent-sdk-py/tests → ../../target/debug/
_HERE = Path(__file__).parent
BINARY_PATH = str((_HERE / "../../../target/debug/emberlink-agent").resolve())
TEST_PERSONA_ID = "test-persona-001"


def _binary_available() -> bool:
    return os.path.isfile(BINARY_PATH) and os.access(BINARY_PATH, os.X_OK)


skip_no_binary = pytest.mark.skipif(
    not _binary_available(),
    reason=f"binary not built — run: cargo build -p emberlink-agent (expected at {BINARY_PATH})",
)


@pytest.fixture()
def agent(tmp_path: Path):
    """Yield a connected EmberAgent backed by a fresh temp database."""
    db = str(tmp_path / "test.db")
    config = AgentConfig(
        binary_path=BINARY_PATH,
        db_path=db,
        persona_id=TEST_PERSONA_ID,
        label="Integration Test Agent",
    )
    with EmberAgent(config) as a:
        yield a


@skip_no_binary
def test_whoami_returns_persona(agent: EmberAgent) -> None:
    result = agent.whoami()
    assert result.persona_id == TEST_PERSONA_ID
    assert result.label == "Integration Test Agent"


@skip_no_binary
def test_list_grants_returns_list(agent: EmberAgent) -> None:
    grants = agent.list_grants()
    assert isinstance(grants, list)


@skip_no_binary
def test_request_grant_returns_request_id(agent: EmberAgent) -> None:
    result = agent.request_grant(scope="test")
    assert isinstance(result.request_id, str)
    assert len(result.request_id) > 0
    assert result.status == "pending"


@skip_no_binary
def test_request_grant_with_all_params(agent: EmberAgent) -> None:
    result = agent.request_grant(
        scope="ReadCredential",
        resource_id="res-abc",
        duration_secs=3600,
        reason="integration test",
    )
    assert result.status == "pending"
    assert result.request_id.startswith("req-")


@skip_no_binary
def test_grant_status_missing_id_returns_error(agent: EmberAgent) -> None:
    # grant_status for a truly nonexistent ID returns NOT_FOUND.
    with pytest.raises(EmberAgentError) as exc_info:
        agent.grant_status("definitely-does-not-exist")
    assert exc_info.value.code == "NOT_FOUND"


@skip_no_binary
def test_grant_status_not_found(agent: EmberAgent) -> None:
    with pytest.raises(EmberAgentError) as exc_info:
        agent.grant_status("nonexistent-grant-id")
    assert exc_info.value.code == "NOT_FOUND"


@skip_no_binary
def test_use_credential_grant_not_found(agent: EmberAgent) -> None:
    with pytest.raises(EmberAgentError) as exc_info:
        agent.use_credential(grant_id="nonexistent-grant", credential_id="cred-1")
    assert exc_info.value.code == "NOT_FOUND"


@skip_no_binary
def test_invalid_method_returns_unknown_method_error(tmp_path: Path) -> None:
    """Send an unknown method directly over stdio to verify the error code."""
    db = str(tmp_path / "test.db")
    proc = subprocess.Popen(
        [BINARY_PATH, "--db", db, "--persona", TEST_PERSONA_ID],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        payload = json.dumps({"id": "req-bad", "method": "fly_to_moon", "params": {}}) + "\n"
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(payload.encode())
        proc.stdin.flush()
        raw = proc.stdout.readline()
        response = json.loads(raw.decode())
        assert "error" in response
        assert response["error"]["code"] == "UNKNOWN_METHOD"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
