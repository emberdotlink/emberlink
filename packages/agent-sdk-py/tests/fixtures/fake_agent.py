#!/usr/bin/env python3
"""Fake emberlink-agent for unit testing.

Protocol:
  - Reads JSON-RPC requests from stdin, one per line.
  - For the FIRST request received, emits a ``grant_revoked`` notification
    BEFORE the response, to exercise server-initiated push mid-stream.
  - Responds to "whoami" with a fixed persona.
  - Responds to "list_grants" with an empty list.
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


NOTIFICATION = {
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

    if first:
        first = False
        write(NOTIFICATION)

    if method == "whoami":
        write({"id": req_id, "result": {"persona_id": "persona-test-001", "label": "Fake Agent"}})
    elif method == "list_grants":
        write({"id": req_id, "result": []})
    else:
        write({"id": req_id, "error": {"code": "UNKNOWN_METHOD", "message": f"unknown method: {method}"}})
