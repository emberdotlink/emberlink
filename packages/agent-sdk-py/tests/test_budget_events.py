"""Tests for budget.warning and budget.exhausted server-pushed notifications.

Uses the same fake subprocess agent (tests/fixtures/fake_agent.py) as the
grant_revoked tests. The fake agent supports 'emit_budget_warning',
'emit_budget_exhausted', and 'emit_malformed_budget' trigger methods.

Note: the fake agent always emits a grant_revoked notification on the FIRST
request. Tests that don't care about grant_revoked simply call whoami() first
(with no on_grant_revoked handler) to consume the first-request side-effect,
then exercise the budget notification paths.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

from emberlink_agent.client import EmberAgent, EmberAgentError
from emberlink_agent.types import (
    AgentConfig,
    BudgetExhaustedNotification,
    BudgetWarningNotification,
)

_FIXTURE = str((Path(__file__).parent / "fixtures" / "fake_agent.py").resolve())


def _make_agent() -> EmberAgent:
    """Return an EmberAgent wired to run the fake_agent fixture script."""
    agent = EmberAgent(AgentConfig(
        binary_path=sys.executable,
        db_path="/dev/null",
        persona_id="persona-test-001",
    ))

    original_connect = agent.connect  # noqa: F841

    def patched_connect() -> None:
        import subprocess
        import threading as _t

        cmd = [sys.executable, _FIXTURE, "--db", "/dev/null", "--persona", "persona-test-001"]
        agent._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        agent._responses = {}
        agent._reader_thread = _t.Thread(target=agent._read_loop, daemon=True)
        agent._reader_thread.start()

    agent.connect = patched_connect  # type: ignore[method-assign]
    return agent


def test_budget_warning_callback_fires() -> None:
    """on_budget_warning fires with correct payload when daemon pushes budget.warning."""
    received: list[BudgetWarningNotification] = []
    event = threading.Event()

    agent = _make_agent()
    agent.on_budget_warning = lambda n: (received.append(n), event.set())

    with agent:
        # Consume the mandatory first-request grant_revoked side-effect.
        agent.whoami()
        # Trigger budget.warning notification.
        agent._send("emit_budget_warning", {
            "grant_id": "grant-abc",
            "statement_sid": "stmt-session",
            "axis": "tokens",
            "used": 16000,
            "budget": 20000,
            "percent": 80,
        })
        event.wait(timeout=2)

    assert len(received) == 1
    n = received[0]
    assert n.grant_id == "grant-abc"
    assert n.statement_sid == "stmt-session"
    assert n.axis == "tokens"
    assert n.used == 16000.0
    assert n.budget == 20000.0
    assert n.percent == 80.0
    assert n.threshold_band == "warning"


def test_budget_exhausted_callback_fires() -> None:
    """on_budget_exhausted fires with correct payload when daemon pushes budget.exhausted."""
    received: list[BudgetExhaustedNotification] = []
    event = threading.Event()

    agent = _make_agent()
    agent.on_budget_exhausted = lambda n: (received.append(n), event.set())

    with agent:
        agent.whoami()
        agent._send("emit_budget_exhausted", {
            "grant_id": "grant-abc",
            "statement_sid": "stmt-session",
            "axis": "tokens",
            "used": 20000,
            "budget": 20000,
            "percent": 100,
        })
        event.wait(timeout=2)

    assert len(received) == 1
    n = received[0]
    assert n.grant_id == "grant-abc"
    assert n.statement_sid == "stmt-session"
    assert n.axis == "tokens"
    assert n.used == 20000.0
    assert n.budget == 20000.0
    assert n.percent == 100.0
    assert n.threshold_band == "exhausted"


def test_subsequent_request_works_after_budget_warning() -> None:
    """A subsequent request/response cycle succeeds after a budget.warning was pushed."""
    agent = _make_agent()

    with agent:
        # Consume first-request grant_revoked.
        agent.whoami()
        # Trigger budget warning notification.
        agent._send("emit_budget_warning", {})
        # A further request must correlate correctly.
        grants = agent.list_grants()

    assert grants == []


def test_subsequent_request_works_after_budget_exhausted() -> None:
    """A subsequent request/response cycle succeeds after a budget.exhausted was pushed."""
    agent = _make_agent()

    with agent:
        agent.whoami()
        agent._send("emit_budget_exhausted", {})
        grants = agent.list_grants()

    assert grants == []


def test_budget_warning_callback_exception_does_not_crash_reader() -> None:
    """An exception from on_budget_warning must not crash the reader thread."""
    agent = _make_agent()

    def bad_warning_callback(n: BudgetWarningNotification) -> None:
        raise RuntimeError("intentional error from warning callback")

    agent.on_budget_warning = bad_warning_callback

    with agent:
        agent.whoami()
        agent._send("emit_budget_warning", {})
        # Reader thread must still be alive — second request must succeed.
        second = agent.list_grants()

    assert second == []


def test_budget_exhausted_callback_exception_does_not_crash_reader() -> None:
    """An exception from on_budget_exhausted must not crash the reader thread."""
    agent = _make_agent()

    def bad_exhausted_callback(n: BudgetExhaustedNotification) -> None:
        raise RuntimeError("intentional error from exhausted callback")

    agent.on_budget_exhausted = bad_exhausted_callback

    with agent:
        agent.whoami()
        agent._send("emit_budget_exhausted", {})
        second = agent.list_grants()

    assert second == []


def test_malformed_budget_warning_delivered_via_callback() -> None:
    """Malformed budget.warning payload (empty params) is still delivered to on_budget_warning.

    The SDK constructs the dataclass from whatever the daemon sends, defaulting
    missing fields to empty string / 0. The caller is responsible for validation.
    """
    received: list[BudgetWarningNotification] = []
    event = threading.Event()

    agent = _make_agent()
    agent.on_budget_warning = lambda n: (received.append(n), event.set())

    with agent:
        agent.whoami()
        agent._send("emit_malformed_budget", {})
        event.wait(timeout=2)

    assert len(received) == 1
    n = received[0]
    # All fields default when absent.
    assert n.grant_id == ""
    assert n.statement_sid == ""
    assert n.axis == ""
    assert n.used == 0.0
    assert n.budget == 0.0
    assert n.percent == 0.0
    assert n.threshold_band == "warning"


def test_no_budget_warning_handler_notification_does_not_crash() -> None:
    """budget.warning notification with no handler set must not crash."""
    agent = _make_agent()

    with agent:
        agent.whoami()
        # No on_budget_warning set — should silently drop.
        result = agent._send("emit_budget_warning", {})

    assert result == {"ok": True}


def test_no_budget_exhausted_handler_notification_does_not_crash() -> None:
    """budget.exhausted notification with no handler set must not crash."""
    agent = _make_agent()

    with agent:
        agent.whoami()
        result = agent._send("emit_budget_exhausted", {})

    assert result == {"ok": True}


def test_grant_revoked_and_budget_callbacks_are_independent() -> None:
    """Firing each notification type once — each callback fires exactly once, no cross-fire."""
    revoked_count = 0
    warning_count = 0
    exhausted_count = 0

    agent = _make_agent()
    agent.on_grant_revoked = lambda _: None  # absorb the first-request side-effect
    agent.on_budget_warning = lambda _: None
    agent.on_budget_exhausted = lambda _: None

    # Patch to count calls.
    revoked_events: list[object] = []
    warning_events: list[object] = []
    exhausted_events: list[object] = []

    agent.on_grant_revoked = lambda n: revoked_events.append(n)
    agent.on_budget_warning = lambda n: warning_events.append(n)
    agent.on_budget_exhausted = lambda n: exhausted_events.append(n)

    with agent:
        # First request triggers grant_revoked (counted above).
        agent.whoami()
        agent._send("emit_budget_warning", {})
        agent._send("emit_budget_exhausted", {})

        # Give the reader thread a moment to deliver all notifications.
        import time
        time.sleep(0.1)

    assert len(revoked_events) == 1
    assert len(warning_events) == 1
    assert len(exhausted_events) == 1


def test_axis_values_round_trip() -> None:
    """All four axis values round-trip through the budget.warning notification."""
    axes = ["tokens", "cents", "requests", "wall_clock_secs"]

    for axis in axes:
        received: list[BudgetWarningNotification] = []
        event = threading.Event()

        agent = _make_agent()
        agent.on_budget_warning = lambda n: (received.append(n), event.set())

        with agent:
            agent.whoami()
            agent._send("emit_budget_warning", {
                "grant_id": f"grant-{axis}",
                "statement_sid": "stmt-001",
                "axis": axis,
                "used": 80,
                "budget": 100,
                "percent": 80,
            })
            event.wait(timeout=2)

        assert len(received) == 1, f"No notification received for axis={axis}"
        assert received[0].axis == axis, f"axis mismatch for {axis}"
