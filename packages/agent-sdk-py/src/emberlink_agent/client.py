from __future__ import annotations

import json
import subprocess
import threading
from typing import Any, Callable, Optional

from .types import (
    AgentConfig,
    BudgetExhaustedNotification,
    BudgetWarningNotification,
    CredentialValue,
    GrantInfo,
    GrantRevokedNotification,
    GrantStatusResult,
    RequestGrantResult,
    UseCredentialResult,
    WhoAmIResult,
)

_DEFAULT_TIMEOUT_SECS = 30


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
        self._responses: dict[str, tuple[threading.Event, dict[str, Any]]] = {}
        self._reader_thread: threading.Thread | None = None

        # Called when the daemon pushes a ``grant_revoked`` notification.
        # Assign before calling ``connect()`` to avoid missing early notifications.
        self.on_grant_revoked: Optional[Callable[[GrantRevokedNotification], None]] = None

        # Called when the daemon pushes a ``budget.warning`` notification (80% or 95% threshold).
        # Assign before calling ``connect()`` to avoid missing early notifications.
        self.on_budget_warning: Optional[Callable[[BudgetWarningNotification], None]] = None

        # Called when the daemon pushes a ``budget.exhausted`` notification (100% threshold).
        # Assign before calling ``connect()`` to avoid missing early notifications.
        self.on_budget_exhausted: Optional[Callable[[BudgetExhaustedNotification], None]] = None

    def connect(self) -> None:
        cmd = [
            self._config.binary_path,
            "--db", self._config.db_path,
            "--persona", self._config.persona_id,
        ]
        if self._config.label is not None:
            cmd += ["--label", self._config.label]
        if self._config.daemon_socket is not None:
            cmd += ["--daemon-socket", self._config.daemon_socket]
        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._responses = {}
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self) -> None:
        assert self._process is not None
        assert self._process.stdout is not None
        for line_bytes in self._process.stdout:
            line = line_bytes.decode("utf-8").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") is not None:
                req_id = msg["id"]
                with self._lock:
                    slot = self._responses.get(req_id)
                if slot is not None:
                    slot[1].update(msg)
                    slot[0].set()
            else:
                method = msg.get("method")
                params = msg.get("params", {})
                if method == "grant_revoked":
                    cb = self.on_grant_revoked
                    if cb is not None:
                        notif = GrantRevokedNotification(
                            grant_id=params.get("grant_id", ""),
                            persona_id=params.get("persona_id", ""),
                        )
                        try:
                            cb(notif)
                        except Exception:
                            pass
                elif method == "budget.warning":
                    cb_w = self.on_budget_warning
                    if cb_w is not None:
                        notif_w = BudgetWarningNotification(
                            grant_id=params.get("grant_id", ""),
                            statement_sid=params.get("statement_sid", ""),
                            axis=params.get("axis", ""),
                            used=float(params.get("used", 0)),
                            budget=float(params.get("budget", 0)),
                            percent=float(params.get("percent", 0)),
                            threshold_band="warning",
                        )
                        try:
                            cb_w(notif_w)
                        except Exception:
                            pass
                elif method == "budget.exhausted":
                    cb_e = self.on_budget_exhausted
                    if cb_e is not None:
                        notif_e = BudgetExhaustedNotification(
                            grant_id=params.get("grant_id", ""),
                            statement_sid=params.get("statement_sid", ""),
                            axis=params.get("axis", ""),
                            used=float(params.get("used", 0)),
                            budget=float(params.get("budget", 0)),
                            percent=float(params.get("percent", 0)),
                            threshold_band="exhausted",
                        )
                        try:
                            cb_e(notif_e)
                        except Exception:
                            pass

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
        # Wake any pending waiters so they don't block forever.
        with self._lock:
            pending = list(self._responses.values())
        for event, slot in pending:
            if not event.is_set():
                slot.update({"error": {"code": "CLOSED", "message": "agent process closed"}})
                event.set()

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
        event = threading.Event()
        slot: dict[str, Any] = {}
        with self._lock:
            self._responses[req_id] = (event, slot)

        payload = {"id": req_id, "method": method, "params": params or {}}
        line = json.dumps(payload) + "\n"

        assert self._process.stdin is not None
        self._process.stdin.write(line.encode("utf-8"))
        self._process.stdin.flush()

        timeout = _DEFAULT_TIMEOUT_SECS
        if not event.wait(timeout=timeout):
            with self._lock:
                self._responses.pop(req_id, None)
            raise EmberAgentError("TIMEOUT", f"no response to {method} within {timeout}s")

        with self._lock:
            self._responses.pop(req_id, None)

        if slot.get("error") is not None:
            err = slot["error"]
            raise EmberAgentError(str(err.get("code", "UNKNOWN")), err.get("message", "unknown error"))

        return slot.get("result")

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
            status=result["status"],
            grant_id=result.get("grant_id"),
            request_id=result.get("request_id"),
            issuer_id=result.get("issuer_id"),
            capability=result.get("capability"),
            expires_at=result.get("expires_at"),
        )

    def use_credential(self, grant_id: str, credential_name: str) -> UseCredentialResult:
        result = self._send(
            "use_credential",
            {"grant_id": grant_id, "credential_id": credential_name},
        )
        cred = result["credential"]
        return UseCredentialResult(
            status=result["status"],
            credential=CredentialValue(
                value=cred["value"],
                scope=cred["scope"],
                grant_id=cred["grant_id"],
            ),
        )
