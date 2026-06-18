# emberlink-mcp

MCP server for Emberlink's daemon-backed authority surface. It speaks
JSON-RPC 2.0 over stdio and is an MCP-shaped client of the local daemon, not a
second trust root.

## Current truth

- daemon-backed by default
- exposes only the canonical daemon control/read tools
- does not expose credential materialization tools
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
| `--label <LABEL>` | `emberlink-mcp` | Human-readable label for this MCP server |
| `--daemon-socket <PATH>` | platform default | Path to the local daemon Unix socket |

## Minimal Claude / MCP Client Wiring

```json
{
  "mcpServers": {
    "ember": {
      "command": "emberlink-mcp"
    }
  }
}
```

Override `--daemon-socket` only for non-standard installs. The default follows
the installed daemon's OS system socket (`/Library/Application Support/Emberlink/run/daemon.sock`
on macOS, `/run/ember/daemon.sock` on Linux).

## Tools

| Tool | Description | Required params |
|---|---|---|
| `session.describe` | Describe a live Runtime Persona attach target | `runtime_persona_id` |
| `catalog.search_actions` | Search the Action Manifest catalog projection | none |
| `access.request` | Request authority for a manifest action | `persona_id`, `action_ref`, `credential_name`, plus `resource_id` or `target` |
| `grant.list` | List active grants visible to a persona | `persona_id` |
| `status.get` | Read daemon status projection | none |
| `evidence.query` | Query receipt evidence | none |
| `evidence.get` | Fetch one receipt/evidence item | `id` |

## Request Shape Notes

### `access.request`

`access.request` is manifest-shaped. The caller names `action_ref`; the daemon
loads the Action Manifest, derives `need`, and mints or submits a composite
grant with one Statement per `need` atom. The caller must provide a concrete
resource selector with either `resource_id` or a typed `target`.

Minimal example:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "access.request",
    "arguments": {
      "persona_id": "persona-123",
      "action_ref": "registry.ember.systems/ember-systems/ember-gh/pr_list@v1",
      "credential_name": "github-token",
      "target": {
        "kind": "github_repo",
        "repo": "emberdotlink/emberlink"
      },
      "ttl_secs": 3600
    }
  }
}
```

Removed fields:

- `action`
- `scope`

Removed MCP tools:

- `whoami`
- `list_grants`
- `request_grant`
- `grant_status`
- `use_credential`
- `list_receipts`
- `get_receipt`
- `grant_budget_status`

## Fail-Closed Behavior

Without a daemon link, canonical tools do not fall back to local state. Tool
failures are surfaced as MCP tool results with `isError: true` when the call
reaches a known tool; removed tool names return JSON-RPC `unknown tool` errors.

## Protocol

- transport: JSON-RPC 2.0 over stdio (newline-delimited)
- MCP protocol version: `2024-11-05`
- maximum line length: 1 MB
