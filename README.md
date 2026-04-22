# Emberlink

**The Grant Warden for AI agents.**

*Keep the keys. Grant the action.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Build](https://github.com/emberdotlink/emberlink/actions/workflows/check.yml/badge.svg)](https://github.com/emberdotlink/emberlink/actions)

## The problem

AI agents need authority to do useful work. Today that means a raw token, a broad OAuth scope, or a platform permission — standing, broad, impossible to revoke cleanly. One prompt injection, one supply-chain bite, one runaway retry loop, and the credential is gone or the bill is $10K.

**Agents should not get credentials. Agents should get grants.** A grant is scoped, time-bound, persona-bound, budget-metered, human-approved, and revocable in one tap. The agent gets authority to *act*, not the key.

## What Emberlink does

The **Ember Warden** runs on your machine. It holds the credentials. Agents never see them. Every agent action flows through the Warden as a **Grant** — carrying scope, TTL, optional token/dollar budget, persona, policy decision, attestation, and a signed **Grant Receipt** when the grant ends.

- **Credential custody without exposure** — your GitHub token, Anthropic key, and database password stay in the local vault. The agent never holds them.
- **Grants — the universal authority primitive** — credential grants, token-budget grants, dollar-budget grants, compute grants. Same primitive, same UX, same audit. See design.
- **Policy + approval** — narrow, approve, deny, or require human approval. Deterministic policy engine, not a prompt.
- **Real-time metering + agent self-moderation** — live token + dollar gauges; agent gets pushed an `on_budget_warning` MCP signal at 80% and can wrap up in-budget.
- **Offline attenuation** — sub-agents inherit a narrower grant; cascade revocation kills the whole chain.
- **Signed Grant Receipts** — every terminated grant emits a durable, signed record of who delegated what to whom, what was narrowed, what the agent did, and when it ended. Exportable JSON.
- **Hardened sandbox** — Docker containers with non-root, `no-new-privileges`, read-only rootfs, `cap-drop=ALL`. Credentials are the isolation boundary, not the network. See design.
- **Runtime-neutral** — MCP protocol surface works with Claude Code, OpenClaw, IronClaw, gbrain, Claude Desktop, Cursor. One Warden, many frameworks.

## Quick demo

```bash
# Install and initialize
cargo install --path crates/emberlink-cli --bin ember
ember init --name "your-name"
ember daemon start

# Create an agent identity and grant it access
ember persona create --name "coding-agent"
ember vault add --name "github-token" --value "ghp_yourtoken"
ember grant create --persona <id> --credential github-token --scope read --ttl 3600

# Check what's running
ember status
```

See [QUICKSTART.md](QUICKSTART.md) for the full walkthrough including sandbox setup and approval flows.

## Architecture

```
Human ← ember daemon → Agent (sandboxed)
         ├── socket        Unix socket — agent communication
         ├── vault         Encrypted SQLite — credential storage
         ├── grant         Scope, TTL, rate limits, conditions
         ├── policy        TOML rules — auto-approve / ask / deny
         ├── proxy         localhost HTTP — credential mediation
         ├── approval      JIT escalation — human-in-the-loop
         ├── sandbox       Hardened Docker — non-root, read-only, cap-drop-all, bridge
         ├── dashboard     localhost:3141 — live grants and audit log
         └── audit         Append-only event log
```

## Installation

```bash
# From source (current)
cargo install --path crates/emberlink-cli --bin ember

# crates.io (coming soon)
cargo install emberlink-cli
```

Requires Rust 1.75+. Docker required for sandbox isolation.

## SDKs

| SDK | Package | Status |
|-----|---------|--------|
| Rust | `crates/emberlink-agent` | Available |
| TypeScript | `packages/agent-sdk-ts` (`@emberlink/agent`) | Available |
| Python | `packages/agent-sdk-py` (`emberlink-agent`) | Available |

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

With the daemon running, Claude Code gets MCP tools like `request_grant`, `use_credential`, and `list_grants` that route through the policy engine. Requests that require approval fire a desktop notification and block until you approve from the dashboard or CLI.

## Contributing

Keep changes focused and include local verification evidence.

## License

Apache-2.0
