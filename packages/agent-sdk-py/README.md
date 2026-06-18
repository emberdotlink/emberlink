# emberlink-agent

Experimental Python helper client for the Emberlink agent authorization protocol. It spawns the `emberlink-agent` helper subprocess, which routes daemon-backed methods through the local Ember daemon.

See the [TypeScript counterpart SDK](../agent-sdk-ts/README.md) and the [Emberlink project README](../../README.md).

## Installation

```
pip install emberlink-agent
```

Requires Python 3.10 or later.

### Daemon prerequisite

The `emberlink-agent` binary must be installed and in your PATH. The
`EmberAgent` class spawns it as a subprocess and routes daemon-backed methods
through the local Ember daemon.

Download the binary for your platform from the [GitHub releases page](https://github.com/emberdotlink/emberlink/releases/latest):

| File | Platform |
|------|----------|
| `emberlink-agent-x86_64-apple-darwin.tar.gz` | macOS Intel |
| `emberlink-agent-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `emberlink-agent-x86_64-unknown-linux-gnu.tar.gz` | Linux x86\_64 |
| `emberlink-agent-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 |

```bash
tar xzf emberlink-agent-*.tar.gz
chmod +x emberlink-agent
sudo mv emberlink-agent /usr/local/bin/
```

Or build from source:

```bash
cargo install --path crates/emberlink-agent
```

## Quick start

```python
import os
import sys
from emberlink_agent import AgentConfig, EmberAgent, EmberAgentError

config = AgentConfig(
    db_path=os.environ.get("EMBERLINK_DB", "./emberlink.db"),
    persona_id=os.environ.get("EMBERLINK_PERSONA", "my-agent-persona"),
    daemon_socket=os.environ.get("EMBERLINK_DAEMON_SOCKET"),
)

# Subscribe before connecting so no notifications are missed.
def on_revoked(notif):
    print(f"Grant revoked — stopping work: {notif.grant_id}", flush=True)

def on_budget_warning(notif):
    print(f"Budget warning on {notif.grant_id}: {notif.axis} at {notif.percent}%", flush=True)

try:
    with EmberAgent(config) as agent:
        agent.on_grant_revoked = on_revoked
        agent.on_budget_warning = on_budget_warning

        me = agent.whoami()
        print("Connected as:", me.persona_id)

        grant = agent.request_grant(
            scope="repo:read",
            resource_id="github-token",
            reason="CI run",
        )
        # request_id is an approval id when status is "pending" and a grant id
        # when status is "approved" (for auto-approved policy paths).
        print(f"Grant request: {grant.request_id} — {grant.status}")

        status = agent.grant_status(grant.request_id)
        print("Status:", status.status)

except FileNotFoundError:
    print("Could not start emberlink-agent. Is the binary in your PATH?", file=sys.stderr)
    sys.exit(1)
except EmberAgentError as e:
    print(f"Agent error [{e.code}]: {e.message}", file=sys.stderr)
    sys.exit(1)
```

## API reference

### `EmberAgent`

The primary high-level client. Manages an `emberlink-agent` subprocess and demultiplexes both request/response pairs and server-pushed notifications using a background reader thread.

```python
from emberlink_agent import AgentConfig, EmberAgent
```

#### Constructor

```python
EmberAgent(config: AgentConfig)
```

`AgentConfig` fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `db_path` | `str` | yes | Path to the Emberlink SQLite database |
| `persona_id` | `str` | yes | Persona ID to operate as |
| `binary_path` | `str` | no | Path to `emberlink-agent` binary (default: `"emberlink-agent"`, resolved from PATH) |
| `label` | `str \| None` | no | Optional human-readable label for this persona session |
| `daemon_socket` | `str \| None` | no | Override the platform default daemon socket path |

Use as a context manager or call `connect()` / `close()` manually:

```python
# Context manager (recommended)
with EmberAgent(config) as agent:
    ...

# Manual lifecycle
agent = EmberAgent(config)
agent.connect()
try:
    ...
finally:
    agent.close()
```

#### Methods

**`connect() -> None`**
Spawns the `emberlink-agent` subprocess and starts the background reader thread. Call this before any other method, or use the class as a context manager. Assign notification callbacks (`on_grant_revoked`, `on_budget_warning`, `on_budget_exhausted`) before calling `connect()` to avoid missing early notifications.

**`close() -> None`**
Terminates the subprocess and wakes any threads blocked on pending requests with `{ code: 'CLOSED' }`.

**`whoami() -> WhoAmIResult`**
Returns the active persona identity. Result fields: `persona_id: str`, `label: str | None`.

**`list_grants() -> list[GrantInfo]`**
Returns all grants visible to this persona. Each `GrantInfo` has fields: `grant_id`, `issuer_id`, `capability`, `status`, `expires_at` (optional Unix timestamp).

**`request_grant(scope, resource_id=None, duration_secs=None, reason=None) -> RequestGrantResult`**
Submits a grant request to the daemon. The daemon routes this through active policy; the human may need to approve it via the Ember Warden UI before the grant becomes active.

Parameters: `scope: str` (required), `resource_id: str | None`, `duration_secs: int | None`, `reason: str | None`.
For daemon-backed credential access, `resource_id` should name the credential so
the helper can route the request through daemon policy.

Returns `RequestGrantResult` with fields `request_id: str` and `status: str`:

- `status == "pending"`: `request_id` is an approval/request id
- `status == "approved"`: `request_id` is the issued grant id

**`grant_status(grant_id: str) -> GrantStatusResult`**
Polls the current status of a previously submitted grant request. Returns
`GrantStatusResult` with:

- `request_id` + `status` for a still-pending approval
- `grant_id` + `status` and optional `issuer_id`, `capability`, `expires_at` for an issued grant

Raises `EmberAgentError` with code `NOT_FOUND` if the daemon rejects the id as unknown.

**`use_credential(grant_id: str, credential_name: str) -> UseCredentialResult`**
Retrieves the credential value under an active grant. Returns `UseCredentialResult` with fields `status: str` and `credential: CredentialValue` (`value`, `scope`, `grant_id`). Raises `ACCESS_DENIED` when the daemon refuses the grant or credential access, and `DAEMON_UNAVAILABLE` when the helper cannot reach the daemon.

#### Notification callbacks

Assign these attributes on the `EmberAgent` instance. They are invoked from the internal background reader thread; keep them fast. Exceptions raised inside a callback are silently swallowed — they will not crash the reader thread or unblock pending requests.

**`on_grant_revoked: Callable[[GrantRevokedNotification], None] | None`**
Fires when the daemon pushes a `grant_revoked` notification. Payload fields: `grant_id: str`, `persona_id: str`. Your agent should stop using the affected credential immediately. If you don't care, leave it as `None`.

**`on_budget_warning: Callable[[BudgetWarningNotification], None] | None`**
Fires when a grant's budget Statement crosses the 80% or 95% usage threshold. Payload fields:

```python
@dataclass
class BudgetWarningNotification:
    grant_id: str
    statement_sid: str
    axis: str            # 'tokens' | 'cents' | 'requests' | 'wall_clock_secs'
    used: float
    budget: float
    percent: float
    threshold_band: Literal['warning']
```

**`on_budget_exhausted: Callable[[BudgetExhaustedNotification], None] | None`**
Fires when a grant's budget reaches 100%. Fields are identical to `BudgetWarningNotification` except `threshold_band` is `'exhausted'`. After this fires the grant will be inactive; further `use_credential` calls will raise `GRANT_INACTIVE`.

### Exported types

All types are importable from `emberlink_agent`:

| Type | Description |
|------|-------------|
| `AgentConfig` | Constructor dataclass for `EmberAgent` |
| `WhoAmIResult` | Return type of `whoami()` |
| `GrantInfo` | Element type of `list_grants()` list |
| `RequestGrantResult` | Return type of `request_grant()` |
| `GrantStatusResult` | Return type of `grant_status()` |
| `UseCredentialResult` | Return type of `use_credential()` |
| `CredentialValue` | Nested credential payload inside `UseCredentialResult` |
| `GrantRevokedNotification` | Payload of `on_grant_revoked` |
| `BudgetWarningNotification` | Payload of `on_budget_warning` |
| `BudgetExhaustedNotification` | Payload of `on_budget_exhausted` |
| `BudgetAxis` | `Literal['tokens', 'cents', 'requests', 'wall_clock_secs']` |

## Error handling

All `EmberAgent` methods raise `EmberAgentError` on protocol errors:

```python
from emberlink_agent import EmberAgent, EmberAgentError

with EmberAgent(config) as agent:
    try:
        result = agent.use_credential("grant-123", "my-cred")
    except EmberAgentError as e:
        print(e.code)     # e.g. "GRANT_INACTIVE", "NOT_FOUND"
        print(e.message)
```

Error codes:

| Code | Meaning |
|------|---------|
| `DAEMON_UNAVAILABLE` | The helper could not reach the Ember daemon |
| `ACCESS_DENIED` | The daemon refused the request or credential access |
| `NOT_FOUND` | Grant ID is unknown |
| `UNKNOWN_METHOD` | The agent subprocess does not recognize the method |
| `INVALID_PARAMS` | Required parameters were missing or malformed |
| `CLOSED` | The subprocess exited while a request was in flight |
| `TIMEOUT` | No response within 30 seconds |

**Fail-closed behavior.** If `connect()` raises `FileNotFoundError` (binary not found) or the subprocess exits immediately, no requests can be sent. The SDK does not fall back to an alternative mechanism. This is intentional: the Ember Warden daemon is the authorization authority; if it is unreachable the agent must not proceed as if access were granted.

## Version compatibility

This SDK targets daemon protocol version 0.1 (the `emberlink-agent` subprocess protocol). For the authoritative JSON-RPC schema see `crates/emberlink-agent/src/` in the Emberlink repository.

## Examples

- [`examples/request_credential.py`](examples/request_credential.py) — connect, request a grant, check status
