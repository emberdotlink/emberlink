
Summary:
- Role: canonical install and first-run path
- Decision status: accepted
- Authority state: current
- Implementation status: shipped
- Last reviewed: 2026-05-18
- Supersedes: docs/getting-started.md

# Quickstart

<!-- QUICKSTART-future milestone -->

This is the canonical install and onboarding path for the current product surface.

## Prerequisites

- **Rust 1.75+** — install via [rustup.rs](https://rustup.rs)
- **Docker** (optional) — required only for `ember sandbox` commands

## 1. Install the CLI

```bash
cargo install --path crates/emberlink-cli --bin ember
```

## 2. Provision the daemon

```bash
sudo ember daemon install
```

This is the only canonical install posture. Per design, the daemon runs under a dedicated `ember` service account; the old single-uid / `install-system` split is retired.

## 3. Initialize operator state

```bash
ember init --name "your-name"
```

`ember init` is idempotent. It creates:

- `~/.ember/config.toml`
- `~/.ember/policy.toml`
- `~/.ember/data/daemon.db`
- your initial identity and vault metadata

If the daemon is not yet installed, `ember init` offers to run `sudo ember daemon install` for you and then resumes.

## 4. Confirm the daemon is up

```bash
ember status
```

`sudo ember daemon install` already bootstraps/enables the platform service. `ember status` is the simplest sanity check: confirm the daemon socket is up and the vault / persona state is visible.

Use `ember daemon start` only for manual foreground/dev starts.

## 5. Create a persona and first grant

```bash
ember persona create --name "coding-agent"
ember vault add --name "github-token" --value "ghp_yourtoken"
ember grant create \
  --persona <persona-id> \
  --credential github-token \
  --scope read \
  --ttl 3600
ember grant list
```

That gives you a real persona, one credential in the vault, and one scoped grant to verify the end-to-end loop.

## 6. Check the audit surface

```bash
ember status
ember receipt list
```

The grant boundary only counts if you can see it. The daemon should now be emitting Receipts for credential-bearing actions and state changes.

## Claude Code path

For host-level Claude Code use, the current canonical path is:

```bash
ember init --for claude-code
ls ~/.ember/shadow/gh ~/.ember/shadow/git
ember claude-code
```

`ember init --for claude-code` is the load-bearing step. It installs the shadowed tool shims under `~/.ember/shadow/` and patches the Claude settings the launcher depends on. If the shadow shims are missing, raw `gh` / `git` calls bypass the broker.

### Optional MCP wiring

If you also want the daemon exposed as an MCP server inside Claude Code:

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

The launcher and the MCP server solve different layers: the launcher gives you the current host-side construct path; MCP exposes daemon tools directly.

## Troubleshooting

- **Daemon install issues:** re-run `sudo ember daemon install`; this is the canonical way to repair install posture drift.
- **Claude Code integration issues:** re-run `ember init --for claude-code` and confirm `~/.ember/shadow/` contains the expected shims.
- **Architecture questions:** start with `docs/current-architecture.md`, then use `CONTEXT.md` and the relevant accepted or amended ADRs.

## Related docs

- [`README.md`](README.md) — overview
- `docs/current-architecture.md` — compact current-state map
- `CONTEXT.md` — terminology and invariants
- `docs/adr-index.md` — ADR entrypoint and lifecycle guidance
- `release-notes` — current scope cuts and bounded issues
