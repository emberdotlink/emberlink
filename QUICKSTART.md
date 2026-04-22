# Quickstart

Get ember running in under 5 minutes.

## Install

```bash
cargo install --path crates/emberlink-cli --bin ember
```

## Initialize

```bash
ember init --name "your-name"
```

This creates:
- Config file at `~/.ember/config.toml`
- Policy file at `~/.ember/policy.toml` (default rules)
- SQLite database at `~/.ember/data/daemon.db`
- Root persona (your identity)
- Vault encryption key stored in the OS keychain

Output shows each path and the keychain status. Ends with `Run 'ember daemon start' to start the daemon.`

## Start the daemon

```bash
ember daemon start
```

Or run in the background:

```bash
ember daemon start --background
```

The daemon prints on startup:
- **Socket**: `~/.ember/run/daemon.sock` (agent communication)
- **Database**: `~/.ember/data/daemon.db`
- **PID**: process ID
- **Dashboard**: http://localhost:3141 (browser UI; approve/deny/revoke require a CSRF token embedded in the page — curl-style POSTs from other origins are rejected)

Stop with `Ctrl+C` (foreground) or `ember daemon stop` (both modes).

## Create an agent persona

```bash
ember persona create --name "coding-agent"
```

Note the persona ID from the output.

## Add a credential

```bash
ember vault add --name "github-token" --value "ghp_yourtoken"
```

## Grant access

```bash
ember grant create \
  --persona <persona-id> \
  --credential github-token \
  --scope read \
  --ttl 3600
```

Optional conditions: `--rate-limit 10`, `--hours-start 9 --hours-end 17`, `--allowed-targets "github.com,api.github.com"`, `--delegation-depth 1`

## Create a sandbox

```bash
ember sandbox create --name "coding-agent" --image ubuntu:24.04
```

Requires Docker. The sandbox runs the agent in an isolated container with access only to what its grants allow.

## Check status

```bash
ember status
```

Shows active personas, grants, running sandboxes, pending approvals, and recent audit events.

## Claude Code integration

Route Claude Code's tool calls through the ember daemon as an MCP server. Add to `~/.claude/settings.json`:

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

With the daemon running, Claude Code gets five MCP tools that route through the policy engine:
- `whoami` — get agent identity
- `list_grants` — list active grants
- `request_grant` — request a new grant (may require approval)
- `grant_status` — check grant status
- `use_credential` — use a credential via an active grant

Requests that require approval fire a desktop notification and block until you approve from the dashboard or CLI.

Confirm wiring: start the daemon, then in Claude Code run `/mcp` to verify `ember` is connected, then call `whoami` to confirm the agent identity comes back.

## Scope narrowing

When approving a request, you can narrow the scope:

```bash
ember approval narrow <approval-id> --scope "read"
```

This creates a grant with reduced permissions instead of the full requested scope.

## View audit log

```bash
ember audit show --limit 20
ember audit show --agent <persona-id>
```

## Manage approvals

```bash
ember approval list
ember approval approve <id>
ember approval deny <id> --reason "out of scope"
ember approval narrow <id> --scope read
```

## Stop the daemon

```bash
ember daemon stop
```

## Troubleshooting

**Machine-readable status for scripting** — pass `--json` to get a single JSON object with all status fields:
```bash
ember status --json | jq .
```
This outputs `version`, `daemon` (running/pid/socket), `personas` count, `grants`, `approvals`, `standing_grants`, and `audit_events`. Useful for CI health checks and monitoring scripts.

**Daemon already running**
```
ember daemon status
ember daemon stop && ember daemon start
```

**Keyring permission denied** — ember stores the vault encryption key in the OS keychain. On Linux, install `gnome-keyring` or `kwallet`, or run `ember daemon start` inside a desktop session.

**Docker not installed** — the sandbox commands require Docker. Install Docker Desktop (macOS/Windows) or Docker Engine (Linux). The rest of ember works without it; skip `ember sandbox create` if you don't need container isolation.

## Next steps

- Daemon vision — what the daemon becomes
- Grant conditions — rate limits, time windows, allow lists
- Approval flow — JIT escalation for agent requests
- Policy syntax — `ember policy show` / `ember policy eval <action>`

## Auto-start on login

### macOS
```bash
cp contrib/ember-daemon.plist ~/Library/LaunchAgents/link.ember.daemon.plist
launchctl load ~/Library/LaunchAgents/link.ember.daemon.plist
```

### Linux (systemd)
```bash
mkdir -p ~/.config/systemd/user
cp contrib/ember-daemon.service ~/.config/systemd/user/
systemctl --user enable ember-daemon
systemctl --user start ember-daemon
```

---

**The trust layer for AI agents.** [ember.link](https://ember.link)
