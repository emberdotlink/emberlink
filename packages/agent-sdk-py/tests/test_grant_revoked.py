"""Tests for server-pushed grant_revoked notifications.

Uses a fake subprocess agent (tests/fixtures/fake_agent.py) to avoid requiring
a real emberlink-agent binary. The fake agent emits a grant_revoked notification
before its first response to exercise notification demux in the reader thread.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

from emberlink_agent.client import EmberAgent, EmberAgentError
from emberlink_agent.types import AgentConfig, GrantRevokedNotification

_FIXTURE = str((Path(__file__).parent / "fixtures" / "fake_agent.py").resolve())


@pytest.fixture()
def fake_agent() -> AgentConfig:
    return AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
        label=None,
    )


def _make_agent(config: AgentConfig) -> EmberAgent:
    """Return an EmberAgent wired to run the fake_agent fixture script."""
    agent = EmberAgent(config)
    # Patch binary_path to python + fixture so subprocess runs the fake daemon.
    agent._config = AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
        label=None,
    )
    # Override connect to inject the fixture script as an argument.
    original_connect = agent.connect

    def patched_connect() -> None:
        import subprocess

        cmd = [sys.executable, _FIXTURE, "--db", "/dev/null", "--persona", "persona-test-001"]
        agent._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        agent._responses = {}
        import threading as _t

        agent._reader_thread = _t.Thread(target=agent._read_loop, daemon=True)
        agent._reader_thread.start()

    agent.connect = patched_connect  # type: ignore[method-assign]
    return agent


def test_grant_revoked_callback_fires() -> None:
    """Notification arrives before the first response; callback must fire."""
    received: list[GrantRevokedNotification] = []
    event = threading.Event()

    agent = _make_agent(AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
    ))

    def on_revoked(notif: GrantRevokedNotification) -> None:
        received.append(notif)
        event.set()

    agent.on_grant_revoked = on_revoked

    with agent:
        result = agent.whoami()
        # Wait up to 2s for the notification to arrive (it arrives before the response
        # so it should already be delivered, but give the thread a moment).
        event.wait(timeout=2)

    assert result.persona_id == "persona-test-001"
    assert result.label == "Fake Agent"
    assert len(received) == 1
    assert received[0].grant_id == "grant-test-001"
    assert received[0].persona_id == "persona-test-001"


def test_subsequent_request_works_after_notification() -> None:
    """A second request/response cycle succeeds after a notification was pushed."""
    agent = _make_agent(AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
    ))

    with agent:
        # First call triggers the notification push (but we ignore it here).
        first = agent.whoami()
        # Second call exercises the correlation logic after a notification.
        second = agent.list_grants()

    assert first.persona_id == "persona-test-001"
    assert second == []


def test_unknown_method_error_after_notification() -> None:
    """Error responses are delivered correctly after a notification has been pushed."""
    agent = _make_agent(AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
    ))

    with agent:
        # First call triggers the notification.
        agent.whoami()
        # Now send something the fake daemon doesn't know.
        with pytest.raises(EmberAgentError) as exc_info:
            agent._send("fly_to_moon")
    assert exc_info.value.code == "UNKNOWN_METHOD"


def test_callback_exception_does_not_crash_reader() -> None:
    """An exception raised by on_grant_revoked must not crash the reader thread."""
    agent = _make_agent(AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
    ))

    def bad_callback(notif: GrantRevokedNotification) -> None:
        raise RuntimeError("intentional error from test callback")

    agent.on_grant_revoked = bad_callback

    with agent:
        result = agent.whoami()
        # The reader thread must still be alive — the second request must succeed.
        second = agent.list_grants()

    assert result.persona_id == "persona-test-001"
    assert second == []
