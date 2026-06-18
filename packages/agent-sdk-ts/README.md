# @emberlink/agent

Experimental TypeScript helper client for the Emberlink agent authorization protocol. It spawns the `emberlink-agent` helper subprocess, which routes daemon-backed methods through the local Ember daemon.

See the [Python counterpart SDK](../agent-sdk-py/README.md) and the [Emberlink project README](../../README.md).

## Installation

```
npm install @emberlink/agent
```

Requires Node.js 18 or later.

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

```typescript
import { EmberAgent, EmberAgentError } from '@emberlink/agent';

const agent = new EmberAgent({
  dbPath: process.env.EMBERLINK_DB ?? './emberlink.db',
  personaId: process.env.EMBERLINK_PERSONA ?? 'my-agent-persona',
  daemonSocket: process.env.EMBERLINK_DAEMON_SOCKET,
});

// Subscribe before connecting so no notifications are missed.
agent.onGrantRevoked = ({ grant_id }) => {
  console.warn('Grant revoked — stopping work:', grant_id);
};

agent.onBudgetWarning = ({ grant_id, axis, percent }) => {
  console.warn(`Budget warning on ${grant_id}: ${axis} at ${percent}%`);
};

try {
  await agent.connect();
} catch (err) {
  // DAEMON_UNAVAILABLE: binary not found or failed to start.
  console.error('Could not start emberlink-agent. Is the binary in your PATH?', err);
  process.exit(1);
}

const me = await agent.whoami();
console.log('Connected as:', me.persona_id);

const grant = await agent.requestGrant({
  scope: 'repo:read',
  resource_id: 'github-token',
  reason: 'CI run',
});
// request_id is an approval id when status is "pending" and a grant id when
// status is "approved" (for auto-approved policy paths).
console.log('Grant request:', grant.request_id, '—', grant.status);

const status = await agent.grantStatus(grant.request_id);
console.log('Status:', status.status);

agent.close();
```

## API reference

### `EmberAgent`

The primary high-level client. Manages an `emberlink-agent` subprocess and demultiplexes both request/response pairs and server-pushed notifications on a single stdout pipe.

```typescript
import { EmberAgent } from '@emberlink/agent';
```

#### Constructor

```typescript
new EmberAgent(config: AgentConfig)
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dbPath` | `string` | yes | Path to the Emberlink SQLite database |
| `personaId` | `string` | yes | Persona ID to operate as |
| `binaryPath` | `string` | no | Path to `emberlink-agent` binary (default: resolved from PATH) |
| `label` | `string` | no | Optional human-readable label for this persona session |
| `daemonSocket` | `string` | no | Override the platform default daemon socket path |

#### Methods

**`connect(): Promise<void>`**
Spawns the `emberlink-agent` subprocess and begins reading its stdout. Call this before any other method. Assign notification callbacks (`onGrantRevoked`, `onBudgetWarning`, `onBudgetExhausted`) before calling `connect()` to avoid missing early notifications.

**`close(): void`**
Kills the subprocess. Any pending requests reject with `{ code: 'CLOSED' }`.

**`whoami(): Promise<WhoAmIResult>`**
Returns the active persona identity. Result shape: `{ persona_id: string; label?: string }`.

**`listGrants(): Promise<GrantInfo[]>`**
Returns all grants visible to this persona. Each element is `{ grant_id, issuer_id, capability, status, expires_at? }`.

**`requestGrant(params: RequestGrantParams): Promise<RequestGrantResult>`**
Submits a grant request to the daemon. The daemon routes this through active policy; the human may need to approve it via the Ember Warden UI before the grant becomes active.

Parameters: `{ scope: string; resource_id?: string; duration_secs?: number; reason?: string }`.
For daemon-backed credential access, `resource_id` should name the credential so
the helper can route the request through daemon policy.

Returns `{ request_id: string; status: string }`:

- `status: "pending"`: `request_id` is an approval/request id
- `status: "approved"`: `request_id` is the issued grant id

**`grantStatus(grantId: string): Promise<GrantStatusResult>`**
Polls the current status of a previously submitted grant request. Returns one
of:

- `{ request_id: string; status: string }` for a still-pending approval
- `{ grant_id: string; status: string; issuer_id?: string; capability?: string; expires_at?: number }` for an issued grant

Throws `NOT_FOUND` if the daemon rejects the id as unknown.

**`useCredential(params: UseCredentialParams): Promise<CredentialResult>`**
Retrieves the credential value under an active grant. Parameters:
`{ grant_id: string; credential_name: string }`. Returns
`{ status: string; credential: { value: string; scope: string; grant_id: string } }`.
Throws `ACCESS_DENIED` when the daemon refuses the grant or credential access,
and `DAEMON_UNAVAILABLE` when the helper cannot reach the daemon.

#### Notification callbacks

Assign these properties on the `EmberAgent` instance before calling `connect()`. They are invoked by the internal line handler on the thread that processes stdout; keep them fast. Exceptions thrown inside a callback are silently swallowed — they will not crash the line handler or reject pending requests.

**`onGrantRevoked?: (params: GrantRevokedNotification) => void`**
Fires when the daemon pushes a `grant_revoked` notification. Payload: `{ grant_id: string; persona_id: string }`. Your agent should stop using the affected credential immediately. If you don't care, omit the handler.

**`onBudgetWarning?: (params: BudgetWarningNotification) => void`**
Fires when a grant's budget Statement crosses the 80% or 95% usage threshold. Payload:

```typescript
{
  grant_id: string;
  statement_sid: string;
  axis: 'tokens' | 'cents' | 'requests' | 'wall_clock_secs';
  used: number;
  budget: number;
  percent: number;
  threshold_band: 'warning';
}
```

**`onBudgetExhausted?: (params: BudgetExhaustedNotification) => void`**
Fires when a grant's budget reaches 100%. Payload is identical to `BudgetWarningNotification` except `threshold_band` is `'exhausted'`. After this fires the grant will be inactive; further `useCredential` calls will fail with `GRANT_INACTIVE`.

### Exported types

All types are re-exported from the package root:

| Type | Description |
|------|-------------|
| `AgentConfig` | Constructor options for `EmberAgent` |
| `WhoAmIResult` | Return type of `whoami()` |
| `GrantInfo` | Element type of `listGrants()` array |
| `RequestGrantParams` | Parameters for `requestGrant()` |
| `RequestGrantResult` | Return type of `requestGrant()` |
| `GrantStatusResult` | Return type of `grantStatus()` |
| `UseCredentialParams` | Parameters for `useCredential()` |
| `CredentialResult` | Return type of `useCredential()` |
| `GrantRevokedNotification` | Payload of `onGrantRevoked` |
| `BudgetWarningNotification` | Payload of `onBudgetWarning` |
| `BudgetExhaustedNotification` | Payload of `onBudgetExhausted` |
| `BudgetAxis` | `'tokens' \| 'cents' \| 'requests' \| 'wall_clock_secs'` |

## Error handling

All methods on `EmberAgent` throw `EmberAgentError` on protocol errors. Catch it by checking `instanceof`:

```typescript
import { EmberAgent, EmberAgentError } from '@emberlink/agent';

try {
  const status = await agent.grantStatus('nonexistent-id');
} catch (err) {
  if (err instanceof EmberAgentError) {
    console.error(`[${err.code}] ${err.message}`);
  }
}
```

Error codes:

| Code | Meaning |
|------|---------|
| `DAEMON_UNAVAILABLE` | The helper could not reach the Ember daemon |
| `ACCESS_DENIED` | The daemon refused the request or credential access |
| `NOT_FOUND` | Grant ID is unknown |
| `UNKNOWN_METHOD` | The agent subprocess does not recognize the method |
| `INVALID_PARAMS` | Required parameters were missing or malformed |
| `NOT_CONNECTED` | `connect()` was not called before issuing a request |
| `CLOSED` | The subprocess exited while a request was in flight |
| `TIMEOUT` | No response within 30 seconds |

**Fail-closed behavior.** If `connect()` fails (binary not found, process exit on startup), no requests can be sent. The SDK does not fall back to an alternative mechanism. This is intentional: the Ember Warden daemon is the authorization authority; if it is unreachable the agent must not proceed as if access were granted.

## Version compatibility

This SDK targets daemon protocol version 0.1 (the `emberlink-agent` subprocess protocol). For the authoritative JSON-RPC schema see `crates/emberlink-agent/src/` in the Emberlink repository.

## Examples

- [`examples/request-credential.ts`](examples/request-credential.ts) — connect, request a grant, check status
