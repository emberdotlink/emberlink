# MCP Integration

`emberlink-mcp` is the MCP server for Emberlink’s daemon-backed authority
surface. It is not a second trust root. It is an MCP-shaped client of the
local daemon.

## What it is for

Use MCP when you want daemon tools exposed directly into an MCP-capable agent
environment.

This is a different layer than the managed launchers:

- `ember claude` is the canonical managed launcher path
- `ember codex` is the supported advanced Codex launcher path
- `emberlink-mcp` is the daemon tool surface exposed as MCP

If you are choosing between surfaces, start with
[Choose an integration surface](./choosing-an-integration-surface.md).

## Current truth

- MCP is a real surface
- it talks to the local daemon socket by default
- `--no-daemon` is an explicit fail-closed compatibility mode, not the primary path
- it is part of the build/integration story, not the primary friendly
  onboarding lane

## What it exposes

The current MCP server exposes daemon-shaped tool calls such as:

- `whoami`
- `list_grants`
- `request_grant`
- `grant_status`
- `use_credential`

The wider implementation also carries read-side observability tools for daemon
artifacts such as receipt inspection and grant-budget status.

## Minimal wiring shape

The current MCP shape looks like:

```json
{
  "mcpServers": {
    "ember": {
      "command": "emberlink-mcp",
      "args": [
        "--persona", "my-agent-persona"
      ]
    }
  }
}
```

Do not pass `--daemon-socket` for a normal install. The default follows the
installed daemon's platform socket.

Override it only for non-standard installs. The current platform sockets are:

- macOS: `/Library/Application Support/Emberlink/run/daemon.sock`
- Linux: `/run/ember/daemon.sock`

## Daemon prerequisite

`emberlink-mcp` is not useful without a reachable daemon path.

In the normal host-mode path it expects a working local daemon socket.
Current implementation truth is intentionally fail-closed:

- if the daemon socket is unreachable at startup, the normal MCP path exits
  rather than pretending the tool surface is usable
- if you explicitly disable daemon transport, grant-creating behavior remains
  unavailable rather than falling back to ambient authority

That is the same product boundary as the rest of Emberlink: no daemon, no real
authority path.

## When to use MCP

MCP is the right fit when:

- your host environment already speaks MCP
- you want daemon tools in that environment without using the Ember launcher
- you are comfortable with a power-user / integration posture

If you want the most polished current operator journey, prefer the launcher
path first.

## Tool shape notes

- `request_grant` currently requires `scope`, `resource_id`, and `duration_secs`
- `resource_id` is how the daemon policy path knows which credential-bearing
  action is being requested
- `grant_status` can be polled with either a pending approval/request id or an
  active grant id
- receipt and budget tools are also daemon-backed; they do not fall back to
  local in-process state

Treat MCP as a power-user or integration surface today, not the lead
onboarding path for the pre-release operator story.

## Next page

- [MCP tool reference](../reference/mcp-tools.md)
