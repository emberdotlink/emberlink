# MCP Tool Reference

`emberlink-mcp` is a stdio JSON-RPC 2.0 server that exposes Emberlink daemon
control/read surfaces as MCP tools.

Current truth:

- daemon-backed by default
- only canonical dot-named tools are exposed
- credential materialization is not an MCP tool
- tool failures are returned as MCP tool results with `isError: true`

## Server Shape

- transport: JSON-RPC 2.0 over stdio
- MCP protocol version: `2024-11-05`
- max line length: 1 MB

## Tools

| Tool | Purpose | Required arguments |
|---|---|---|
| `session.describe` | Describe a Runtime Persona attach target | `runtime_persona_id` |
| `catalog.search_actions` | Search Action Manifest catalog projection | none |
| `access.request` | Request authority for a manifest action | `persona_id`, `action_ref`, `credential_name`, plus `resource_id` or `target` |
| `grant.list` | List grants visible to a persona | `persona_id` |
| `status.get` | Read daemon status | none |
| `evidence.query` | Query receipt evidence | none |
| `evidence.get` | Fetch one receipt/evidence item | `id` |

## Important Request Semantics

### `access.request`

`access.request` requires a bundled `action_ref`. The daemon resolves the
action's `need` from the bundled Action Manifest. The caller selects the
concrete resource with either:

- `resource_id`
- typed `target`, currently `{"kind":"github_repo","repo":"owner/name"}`

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

## Fail-Closed Posture

Without a daemon link, canonical tools fail rather than inventing local
authority. Removed tool names return JSON-RPC `unknown tool` errors.
