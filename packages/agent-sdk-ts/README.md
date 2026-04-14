# @emberlink/agent

TypeScript SDK for the Emberlink agent authorization protocol.

## Prerequisites

The `emberlink-agent` binary must be installed before using this SDK.

### Download from GitHub Releases

Download the binary for your platform from:

```
https://github.com/emberdotlink/emberlink/releases/latest
```

Available targets:

| File | Platform |
|------|----------|
| `emberlink-agent-x86_64-apple-darwin.tar.gz` | macOS Intel |
| `emberlink-agent-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `emberlink-agent-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 |
| `emberlink-agent-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 |

Extract and place on PATH:

```bash
tar xzf emberlink-agent-*.tar.gz
chmod +x emberlink-agent
sudo mv emberlink-agent /usr/local/bin/
```

### Build from source

```bash
cargo install --path crates/emberlink-agent
```

### Verify

```bash
emberlink-agent --version
```

## Usage

```typescript
import { EmberAgent } from '@emberlink/agent';

const agent = new EmberAgent({
  dbPath: './emberlink.db',
  personaId: 'your-persona-id',
});

await agent.connect();
const me = await agent.whoami();
const grants = await agent.listGrants();
await agent.close();
```

## Examples

See [`examples/request-credential.ts`](examples/request-credential.ts) for a full flow: connect → whoami → request_grant → check status.

## Configuration

The `emberlink-agent` binary must be in your PATH or specified via `binaryPath`.

```typescript
const agent = new EmberAgent({
  binaryPath: '/usr/local/bin/emberlink-agent',
  dbPath: './emberlink.db',
  personaId: 'your-persona-id',
});
```

## API

### `new EmberAgent(config)`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dbPath` | `string` | yes | Path to the Emberlink SQLite database |
| `personaId` | `string` | yes | Persona ID to operate as |
| `binaryPath` | `string` | no | Path to `emberlink-agent` binary (default: resolved from PATH) |
| `label` | `string` | no | Optional label for the persona |

### Methods

- `connect()` — spawn the agent process; call before any other method
- `close()` — kill the agent process
- `whoami()` — return current persona info
- `listGrants()` — return all grants visible to this persona
- `requestGrant(params)` — submit a grant request; returns `{ request_id, status: "pending" }`
- `grantStatus(grantId)` — check status of a specific grant
- `useCredential(params)` — retrieve a credential under an active grant

### Errors

All methods throw `EmberAgentError` on protocol errors. The error has a `code` string matching one of:
`UNKNOWN_METHOD`, `INVALID_PARAMS`, `STORE_ERROR`, `NOT_FOUND`, `GRANT_INACTIVE`, `NO_CREDENTIAL`, `PARSE_ERROR`
