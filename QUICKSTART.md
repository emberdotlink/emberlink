# Ember Quickstart

Get from zero to a running agent sandbox in 5 minutes.

## Prerequisites

- Rust toolchain (`cargo`)
- Docker (for sandboxes)

## 1. Install

```bash
cargo install --path crates/emberlink-cli --bin ember
```

## 2. Initialize

```bash
ember init --name "Your Name"
```

Creates `~/.ember/` with config, database, and your root identity.

## 3. Start the daemon

```bash
ember daemon start
```

The daemon listens on `~/.ember/run/daemon.sock`. It is your trust broker — every agent request passes through here.

## 4. Add a credential

```bash
ember vault add --name github-token --value ghp_your_token_here
```

Credentials live in the vault. Agents never receive raw values — the daemon proxies and logs every access.

## 5. Create an agent persona

```bash
ember persona create --name coding-agent
```

Note the persona ID from the output. A persona is a scoped identity for an agent — it carries grants, not credentials.

## 6. Grant access

```bash
ember grant create \
  --persona <persona-id> \
  --credential github-token \
  --scope read \
  --ttl 3600
```

The agent now has read access to your GitHub token for 1 hour. The grant auto-expires.

## 7. Create a sandbox

```bash
ember sandbox create --name coding-agent --image ubuntu:24.04
```

The sandbox runs the agent in an isolated container with access only to what its grants allow.

## 8. Check status

```bash
ember grant list --active
ember audit show --limit 10
ember persona list
```

## What just happened

You created a **trust broker** — a daemon that controls which agents can access which credentials, for how long, with what scope. The agent never sees your raw token. The daemon proxies API calls and logs everything.

Grants are scoped, time-bound, and revocable. You stay in control.

## Next steps

- Daemon vision — what the daemon becomes
- Grant conditions — rate limits, time windows, allow lists
- Claude Code integration — run Claude Code in a sandbox (coming soon)
- Approval flow — `ember approval list` for agent requests that need your sign-off

---

**The trust layer for AI agents.** [ember.link](https://ember.link)
