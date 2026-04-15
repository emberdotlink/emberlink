from __future__ import annotations

import json
import socket
from typing import Any, Optional


class DaemonError(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Daemon error {code}: {message}")


class SocketTransport:
    def __init__(self, socket_path: str) -> None:
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._file = None
        self._request_id = 0

    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self._socket_path)
        self._file = self._sock.makefile("rw")

    def close(self) -> None:
        if self._file:
            self._file.close()
        if self._sock:
            self._sock.close()
        self._sock = None
        self._file = None

    def send(self, method: str, params: Any = None) -> Any:
        if not self._sock or not self._file:
            raise RuntimeError("Not connected")

        self._request_id += 1
        request = {
            "id": str(self._request_id),
            "method": method,
            "params": params,
        }
        line = json.dumps(request) + "\n"
        self._file.write(line)
        self._file.flush()

        response_line = self._file.readline()
        if not response_line:
            raise ConnectionError("Connection closed")

        response = json.loads(response_line)
        if response.get("id") != str(self._request_id):
            raise RuntimeError(
                f"Response ID mismatch: expected {self._request_id!r}, got {response.get('id')!r}"
            )

        if response.get("error"):
            err = response["error"]
            raise DaemonError(err["code"], err["message"])

        return response.get("result")

    def ping(self) -> bool:
        result = self.send("ping")
        if isinstance(result, dict):
            return result.get("pong", False)
        return result == "pong"

    def request_grant(
        self,
        persona_id: str,
        credential_name: str,
        scope: str,
        ttl_secs: Optional[int] = None,
    ) -> Any:
        params: dict[str, Any] = {
            "persona_id": persona_id,
            "credential_name": credential_name,
            "scope": scope,
        }
        if ttl_secs is not None:
            params["ttl_secs"] = ttl_secs
        return self.send("request_grant", params)

    def use_credential(self, grant_id: str) -> Any:
        return self.send("use_credential", {"grant_id": grant_id})

    def __enter__(self) -> SocketTransport:
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
