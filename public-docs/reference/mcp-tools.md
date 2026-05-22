

> [!NOTE]
> Support level: **Preview**.
> Source truth: `crates/emberlink-mcp/README.md`, `crates/emberlink-mcp/src/lib.rs`, `crates/emberlink-mcp/src/main.rs`.
# MCP Tool Reference

`emberlink-mcp` is a stdio JSON-RPC 2.0 server that exposes Emberlink daemon
surfaces as MCP tools.

Current truth:

- daemon-backed by default
- `--no-daemon` is an explicit fail-closed compatibility mode
- tool failures are returned as MCP tool results with `isError: true`

## Server shape

- transport: JSON-RPC 2.0 over stdio
- MCP protocol version: `2024-11-05`
- max line length: 1 MB

## Tools

| Tool | Purpose | Required arguments |
|---|---|---|
| `whoami` | Read the current persona/label identity | none |
| `list_grants` | List active grants for the caller persona | none |
| `request_grant` | Request daemon-mediated access to a credential-bearing action | `scope`, `resource_id`, `duration_secs` |
| `grant_status` | Check status of a pending approval id or active grant id | `grant_id` |
| `use_credential` | Redeem an active grant | `grant_id`, `credential_id` |
| `list_receipts` | List emitted Grant Receipts | none |
| `get_receipt` | Fetch one receipt by id | `id` |
| `grant_budget_status` | Read lifecycle/budget state for a grant | `grant_id` |

## Important request semantics

### `request_grant`

`resource_id` is required. The daemon uses it to route the request through the
correct policy path for the targeted credential-bearing action.

Minimal example:

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
      "duration_secs": 3600
    }
  }
}
```

Possible outcomes:

- auto-approved immediately
- queued for approval
- denied

### `grant_status`

`grant_status` accepts either:

- a pending request/approval id from `request_grant`
- an active grant id

The returned JSON shape depends on which kind of id the daemon resolved.

### `use_credential`

`use_credential` requires:

- an active `grant_id`
- the `credential_id` being redeemed

It does not bypass the daemon. The daemon still enforces persona ownership and
grant validity.

## Fail-closed posture

Without a daemon link, these tools should be expected to fail:

- `list_grants`
- `request_grant`
- `grant_status`
- `use_credential`
- `list_receipts`
- `get_receipt`
- `grant_budget_status`

That is intentional. MCP is not supposed to invent local authority if the
daemon is unavailable.

