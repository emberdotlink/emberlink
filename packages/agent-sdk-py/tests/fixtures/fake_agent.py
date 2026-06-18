#!/usr/bin/env python3
"""Fake emberlink-agent for unit testing.

Protocol:
  - Reads JSON-RPC requests from stdin, one per line.
  - For the FIRST request received, emits a ``grant_revoked`` notification
    BEFORE the response, to exercise server-initiated push mid-stream.
  - Responds to "whoami" with a fixed persona.
  - Responds to "list_grants" with an empty list.
  - Responds to "emit_budget_warning": pushes a budget.warning notification then confirms.
  - Responds to "emit_budget_exhausted": pushes a budget.exhausted notification then confirms.
  - Responds to "emit_malformed_budget": pushes a budget.warning with empty params then confirms.
  - Responds to any other method with an UNKNOWN_METHOD error.
  - Exits when stdin closes.

Usage:
  python3 tests/fixtures/fake_agent.py --db /ignored --persona ignored
"""
from __future__ import annotations

import json
import sys


def write(obj: object) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


GRANT_REVOKED_NOTIFICATION = {
    "method": "grant_revoked",
    "params": {
        "grant_id": "grant-test-001",
        "persona_id": "persona-test-001",
    },
}

first = True

for raw in sys.stdin:
    line = raw.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue

    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params", {}) or {}

    if first:
        first = False
        write(GRANT_REVOKED_NOTIFICATION)

    if method == "whoami":
        write({"id": req_id, "result": {"persona_id": "persona-test-001", "label": "Fake Agent"}})
    elif method == "list_grants":
        write({"id": req_id, "result": []})
    elif method == "emit_budget_warning":
        write({
            "method": "budget.warning",
            "params": {
                "grant_id": params.get("grant_id", "grant-budget-001"),
                "statement_sid": params.get("statement_sid", "stmt-001"),
                "axis": params.get("axis", "tokens"),
                "used": params.get("used", 16000),
                "budget": params.get("budget", 20000),
                "percent": params.get("percent", 80),
                "threshold_band": "warning",
            },
        })
        write({"id": req_id, "result": {"ok": True}})
    elif method == "emit_budget_exhausted":
        write({
            "method": "budget.exhausted",
            "params": {
                "grant_id": params.get("grant_id", "grant-budget-001"),
                "statement_sid": params.get("statement_sid", "stmt-001"),
                "axis": params.get("axis", "tokens"),
                "used": params.get("used", 20000),
                "budget": params.get("budget", 20000),
                "percent": params.get("percent", 100),
                "threshold_band": "exhausted",
            },
        })
        write({"id": req_id, "result": {"ok": True}})
    elif method == "emit_malformed_budget":
        # Push budget.warning with empty params to test parse-error handling.
        write({"method": "budget.warning", "params": {}})
        write({"id": req_id, "result": {"ok": True}})
    else:
        write({"id": req_id, "error": {"code": "UNKNOWN_METHOD", "message": f"unknown method: {method}"}})
