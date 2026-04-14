from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

from .types import (
    AgentConfig,
    CredentialValue,
    GrantInfo,
    GrantStatusResult,
    RequestGrantResult,
    UseCredentialResult,
    WhoAmIResult,
)


class EmberAgentError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"EmberAgentError(code={self.code!r}, message={self.message!r})"


class EmberAgent:
    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._process: subprocess.Popen[bytes] | None = None
        self._counter = 0
        self._lock = threading.Lock()

    def connect(self) -> None:
        cmd = [
            self._config.binary_path,
            "--db", self._config.db_path,
            "--persona", self._config.persona_id,
        ]
        if self._config.label is not None:
            cmd += ["--label", self._config.label]
        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    def close(self) -> None:
        if self._process is not None:
            try:
                if self._process.stdin:
                    self._process.stdin.close()
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            finally:
                self._process = None

    def __enter__(self) -> EmberAgent:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"req-{self._counter}"

    def _send(self, method: str, params: dict[str, Any] | None = None) -> Any:
        if self._process is None:
            raise RuntimeError("Not connected. Call connect() or use as context manager.")

        req_id = self._next_id()
        payload = {"id": req_id, "method": method, "params": params or {}}
        line = json.dumps(payload) + "\n"

        assert self._process.stdin is not None
        assert self._process.stdout is not None

        self._process.stdin.write(line.encode())
        self._process.stdin.flush()

        raw = self._process.stdout.readline()
        if not raw:
            raise RuntimeError("Agent process closed stdout unexpectedly.")

        response = json.loads(raw.decode())

        if response.get("id") != req_id:
            raise RuntimeError(
                f"Response ID mismatch: expected {req_id!r}, got {response.get('id')!r}"
            )

        if "error" in response:
            err = response["error"]
            raise EmberAgentError(code=err.get("code", "UNKNOWN"), message=err.get("message", ""))

        return response.get("result")

    def whoami(self) -> WhoAmIResult:
        result = self._send("whoami")
        return WhoAmIResult(
            persona_id=result["persona_id"],
            label=result.get("label"),
        )

    def list_grants(self) -> list[GrantInfo]:
        result = self._send("list_grants")
        return [
            GrantInfo(
                grant_id=g["grant_id"],
                issuer_id=g["issuer_id"],
                capability=g["capability"],
                status=g["status"],
                expires_at=g.get("expires_at"),
            )
            for g in result
        ]

    def request_grant(
        self,
        scope: str,
        resource_id: str | None = None,
        duration_secs: int | None = None,
        reason: str | None = None,
    ) -> RequestGrantResult:
        params: dict[str, Any] = {"scope": scope}
        if resource_id is not None:
            params["resource_id"] = resource_id
        if duration_secs is not None:
            params["duration_secs"] = duration_secs
        if reason is not None:
            params["reason"] = reason
        result = self._send("request_grant", params)
        return RequestGrantResult(
            request_id=result["request_id"],
            status=result["status"],
        )

    def grant_status(self, grant_id: str) -> GrantStatusResult:
        result = self._send("grant_status", {"grant_id": grant_id})
        return GrantStatusResult(
            grant_id=result["grant_id"],
            status=result["status"],
            issuer_id=result.get("issuer_id"),
            capability=result.get("capability"),
            expires_at=result.get("expires_at"),
        )

    def use_credential(self, grant_id: str, credential_id: str) -> UseCredentialResult:
        result = self._send("use_credential", {"grant_id": grant_id, "credential_id": credential_id})
        cred = result["credential"]
        return UseCredentialResult(
            status=result["status"],
            credential=CredentialValue(
                value=cred["value"],
                scope=cred["scope"],
                grant_id=cred["grant_id"],
            ),
        )
