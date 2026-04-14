# emberlink-mcp

MCP server that exposes Emberlink agent authorization as tools — grant requests, credential use, and identity checks over JSON-RPC 2.0 on stdio.

## Prerequisites

- Rust toolchain (stable, via `rustup`)
- An Emberlink event store (SQLite file) — omit `--db` to use an in-memory store for testing

## Build

```bash
cargo build -p emberlink-mcp --release
# binary at: target/release/emberlink-mcp
```

## Claude Desktop config

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "emberlink": {
      "command": "/path/to/target/release/emberlink-mcp",
      "args": [
        "--db", "/path/to/emberlink.db",
        "--persona", "default",
        "--label", "claude-desktop"
      ]
    }
  }
}
```

Replace `/path/to/target/release/emberlink-mcp` with the absolute path to the built binary. The `--db` path should point to your Emberlink event store.

## Tools

| Tool | Description | Required params | Optional params |
|------|-------------|-----------------|-----------------|
| `whoami` | Get the agent's current identity (persona ID and label) | — | — |
| `list_grants` | List all active grants for this agent | — | — |
| `request_grant` | Request a new scoped, time-bound grant | `scope` (string), `duration_secs` (integer) | `resource_id` (string), `reason` (string) |
| `grant_status` | Check the status of a specific grant request | `grant_id` (string) | — |
| `use_credential` | Use a credential through an active grant | `grant_id` (string), `credential_id` (string) | — |

### Example invocations

**whoami** — identify the agent:
```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}
```

**list_grants** — see what the agent can currently do:
```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_grants","arguments":{}}}
```

**request_grant** — ask for access to a scope:
```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_grant","arguments":{
  "scope": "read:passwords",
  "duration_secs": 3600,
  "reason": "filling login form"
}}}
```
Returns `{"status":"pending","request_id":"req-..."}`. The human approves or denies out-of-band.

**grant_status** — poll approval state:
```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"grant_status","arguments":{
  "grant_id": "req-abc123"
}}}
```

**use_credential** — redeem an approved grant:
```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"use_credential","arguments":{
  "grant_id": "grant-abc123",
  "credential_id": "cred-xyz789"
}}}
```

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db <path>` | in-memory | Path to the SQLite event store |
| `--persona <id>` | `default` | Persona ID for the agent session |
| `--label <label>` | `emberlink-mcp` | Human-readable label for this server instance |

## Protocol

- Transport: JSON-RPC 2.0 over stdio (newline-delimited)
- MCP protocol version: `2024-11-05`
- Request size limit: 1 MB per line
- Tool errors are returned as `isError: true` content, not JSON-RPC errors
