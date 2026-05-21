

> [!NOTE]
> Support level: **Preview**.
> Source truth: `docs/current-architecture.md`, `crates/emberlink-mcp/README.md`, `docs/cli-reference.md`.
# MCP Integration

`emberlink-mcp` is the MCP server for Emberlink’s daemon-backed authority
surface. It is not a second trust root. It is an MCP-shaped client of the
local daemon.

## What it is for

Use MCP when you want daemon tools exposed directly into an MCP-capable agent
environment.

This is a different layer than `ember claude-code`:

- `ember claude-code` is the canonical managed launcher path
- `emberlink-mcp` is the daemon tool surface exposed as MCP

If you are choosing between surfaces, start with
[Choose an integration surface](./choosing-an-integration-surface/).

## Current truth

- MCP is a real surface
- it talks to the local daemon socket
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
      "args": ["--daemon-socket", "${HOME}/.ember/run/daemon.sock"]
    }
  }
}
```

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

Treat MCP as a power-user or integration surface today, not the lead
onboarding path for the pre-release operator story.

