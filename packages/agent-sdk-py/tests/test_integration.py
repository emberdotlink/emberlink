"""Integration tests for the emberlink-agent Python SDK.

These tests exercise the public Python wrapper against:
  1. a real latest-daemon socket listener fixture, and
  2. an isolated no-daemon environment to verify fail-closed behavior.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from emberlink_agent.client import EmberAgent, EmberAgentError
from emberlink_agent.types import AgentConfig

_HERE = Path(__file__).parent
_REPO_ROOT = (_HERE / "../../..").resolve()
BINARY_PATH = str((_REPO_ROOT / "target/debug/emberlink-agent").resolve())
FIXTURE_DAEMON_PATH = str(
    (_REPO_ROOT / "target/debug/examples/ember_sdk_fixture_daemon").resolve()
)
TEST_CREDENTIAL_NAME = "github-token"
TEST_CREDENTIAL_VALUE = "ghp_fixture_secret"


def _binary_available(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


skip_no_helper_binary = pytest.mark.skipif(
    not _binary_available(BINARY_PATH),
    reason=f"binary not built — run: cargo build -p emberlink-agent (expected at {BINARY_PATH})",
)

skip_no_live_fixture = pytest.mark.skipif(
    not (_binary_available(BINARY_PATH) and _binary_available(FIXTURE_DAEMON_PATH)),
    reason=(
        "binaries not built — run: cargo build -p emberlink-agent "
        "&& cargo build -p ember-daemon --example ember_sdk_fixture_daemon"
    ),
)


@pytest.fixture()
def live_fixture(tmp_path: Path):
    socket_path = Path(f"/tmp/ember-sdk-py-{uuid4().hex}.sock")
    proc = subprocess.Popen(
        [
            FIXTURE_DAEMON_PATH,
            "--socket",
            str(socket_path),
            "--persona-name",
            "sdk-py-agent",
            "--credential-name",
            TEST_CREDENTIAL_NAME,
            "--credential-value",
            TEST_CREDENTIAL_VALUE,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().strip()
        ready = json.loads(line)
        yield {
            "socket_path": ready["socket_path"],
            "persona_id": ready["persona_id"],
            "credential_name": ready["credential_name"],
            "tmp_path": tmp_path,
        }
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        socket_path.unlink(missing_ok=True)


@pytest.fixture()
def live_agent(live_fixture: dict[str, str | Path]):
    db = str(Path(live_fixture["tmp_path"]) / "test.db")
    config = AgentConfig(
        binary_path=BINARY_PATH,
        db_path=db,
        persona_id=str(live_fixture["persona_id"]),
        label="Integration Test Agent",
        daemon_socket=str(live_fixture["socket_path"]),
    )
    with EmberAgent(config) as agent:
        yield agent


@skip_no_live_fixture
def test_whoami_returns_persona(live_agent: EmberAgent, live_fixture: dict[str, str | Path]) -> None:
    result = live_agent.whoami()
    assert result.persona_id == live_fixture["persona_id"]
    assert result.label == "Integration Test Agent"


@skip_no_live_fixture
def test_list_grants_returns_list(live_agent: EmberAgent) -> None:
    grants = live_agent.list_grants()
    assert isinstance(grants, list)


@skip_no_live_fixture
def test_request_grant_auto_approves_against_live_daemon(
    live_agent: EmberAgent, live_fixture: dict[str, str | Path]
) -> None:
    result = live_agent.request_grant(
        scope="repo:read",
        resource_id=str(live_fixture["credential_name"]),
        reason="integration test",
    )
    assert result.status == "approved"
    assert result.request_id.startswith("grant-")


@skip_no_live_fixture
def test_grant_status_returns_active_grant(
    live_agent: EmberAgent, live_fixture: dict[str, str | Path]
) -> None:
    granted = live_agent.request_grant(
        scope="repo:read",
        resource_id=str(live_fixture["credential_name"]),
        reason="status integration test",
    )
    status = live_agent.grant_status(granted.request_id)
    assert status.status == "active"
    assert status.grant_id == granted.request_id


@skip_no_live_fixture
def test_use_credential_returns_live_daemon_secret(
    live_agent: EmberAgent, live_fixture: dict[str, str | Path]
) -> None:
    granted = live_agent.request_grant(
        scope="repo:read",
        resource_id=str(live_fixture["credential_name"]),
        reason="credential integration test",
    )
    result = live_agent.use_credential(
        grant_id=granted.request_id,
        credential_name=str(live_fixture["credential_name"]),
    )
    assert result.status == "ok"
    assert result.credential.value == TEST_CREDENTIAL_VALUE
    assert result.credential.grant_id == granted.request_id


@skip_no_helper_binary
def test_request_grant_fails_closed_without_daemon(tmp_path: Path) -> None:
    original_home = os.environ.get("HOME")
    os.environ["HOME"] = str(tmp_path)
    config = AgentConfig(
        binary_path=BINARY_PATH,
        db_path=str(tmp_path / "isolated.db"),
        persona_id="persona-no-daemon",
    )
    try:
        with EmberAgent(config) as agent:
            with pytest.raises(EmberAgentError) as exc_info:
                agent.request_grant(
                    scope="repo:read",
                    resource_id="github-token",
                    reason="no daemon proof",
                )
        assert exc_info.value.code == "DAEMON_UNAVAILABLE"
    finally:
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home


@skip_no_helper_binary
def test_invalid_method_returns_unknown_method_error(tmp_path: Path) -> None:
    db = str(tmp_path / "test.db")
    proc = subprocess.Popen(
        [BINARY_PATH, "--db", db, "--persona", "test-persona-001"],
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
