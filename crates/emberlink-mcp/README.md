# emberlink-mcp

MCP server for Emberlink's daemon-backed authority surface. It speaks
JSON-RPC 2.0 over stdio and is an MCP-shaped client of the local daemon, not a
second trust root.

## Current truth

- daemon-backed by default
- talks to the local daemon socket unless `--no-daemon` is passed
- exposes both grant tools and daemon observability tools
- intended as a preview integration surface, not the primary friendly-drop
  onboarding lane

## Build

```bash
cargo build -p emberlink-mcp --release
# binary at: target/release/emberlink-mcp
```

## Usage

```text
emberlink-mcp [OPTIONS]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--persona <ID>` | `default` | Persona ID to operate as |
| `--label <LABEL>` | `emberlink-mcp` | Human-readable label for this MCP server |
| `--daemon-socket <PATH>` | `$HOME/.ember/run/daemon.sock` | Path to the local daemon Unix socket |
| `--db <PATH>` | in-memory | Optional local EventStore path retained for compatibility/tests; daemon-backed grant flows do not require it |
| `--no-daemon` | off | Disable daemon transport and run fail-closed for daemon-backed tools |

## Minimal Claude / MCP client wiring

```json
{
  "mcpServers": {
    "ember": {
      "command": "emberlink-mcp",
      "args": [
        "--persona", "my-agent-persona",
        "--daemon-socket", "${HOME}/.ember/run/daemon.sock"
      ]
    }
  }
}
```

## Tools

| Tool | Description | Required params |
|---|---|---|
| `whoami` | Get the agent identity (`persona_id`, label) | none |
| `list_grants` | List active grants for the caller persona | none |
| `request_grant` | Request daemon-mediated access to a credential-bearing action | `scope`, `resource_id`, `duration_secs` |
| `grant_status` | Check status of a grant or approval id | `grant_id` |
| `use_credential` | Redeem an active grant | `grant_id`, `credential_id` |
| `list_receipts` | List emitted Grant Receipts | none |
| `get_receipt` | Fetch a single receipt by id | `id` |
| `grant_budget_status` | Read budget/lifecycle status for a grant | `grant_id` |

## Request shape notes

### `request_grant`

For daemon-backed flows, `resource_id` is required so the request can be routed
through the daemon policy engine with the correct synthesized action. A minimal
request looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "request_grant",
    "arguments": {
      "scope": "repo:read",
      "resource_id": "github-token",
      "duration_secs": 3600,
      "reason": "CI run"
    }
  }
}
```

When policy auto-approves, the tool can return an already-approved result. When
approval is required, it returns a pending request id that can be polled via
`grant_status`.

### `grant_status`

`grant_status` accepts either:

- a pending approval/request id from `request_grant`
- an active grant id

The returned JSON shape reflects which one the daemon resolved.

## Fail-closed behavior

Without a daemon link, daemon-backed tools do not fall back to local state.

- `request_grant`
- `list_grants`
- `grant_status`
- `use_credential`
- receipt/budget tools

all return tool errors when the daemon is unavailable or when `--no-daemon` is
used.

## Protocol

- transport: JSON-RPC 2.0 over stdio (newline-delimited)
- MCP protocol version: `2024-11-05`
- maximum line length: 1 MB
- tool failures are surfaced as MCP tool results with `isError: true`
