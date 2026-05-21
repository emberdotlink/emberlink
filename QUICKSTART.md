
Summary:
- Role: canonical install and first-run path
- Decision status: accepted
- Authority state: current
- Implementation status: shipped
- Last reviewed: 2026-05-20
- Supersedes: docs/getting-started.md

# Quickstart

<!-- QUICKSTART-future milestone -->

This is the canonical install and onboarding path for the current product surface.

The source mirror may be public before the first public supported build. Until `v0.3.1`, treat this guide as the **current pre-release / friendly-preview path**, not as a broad GA promise. The release boundary lives in design and release-notes.

## Prerequisites

- **Rust 1.95.0** if building from source — install via [rustup.rs](https://rustup.rs)
- **Docker** (optional) — required only for `ember sandbox` commands

## 1. Install the CLI

If you are in the named `v0.3.0` friendly cohort, install the signed preview
artifact that was distributed with your invite. Once `ember` is on your
`PATH`, continue here.

If you are evaluating from the public source mirror rather than the invite-only
friendly-preview build, use the source-build path:

```bash
git clone https://github.com/emberdotlink/emberlink.git
cd emberlink
cargo install --locked --path crates/emberlink-cli --bin ember
```

## 2. Run the canonical onboarding flow

```bash
ember init --for claude-code
```

This is the load-bearing first-run path for friendly testers. It is
idempotent, wires the Claude Code shadow shims, and if the daemon is not yet
installed it offers to run `sudo ember daemon install` for you and then
resumes. Per design, the
daemon runs under a dedicated `ember` service account; the old single-uid /
`install-system` split is retired.

Claude runtime auth is conditional, not magic. If `ANTHROPIC_API_KEY` is in
your environment when you run init, Ember stores it as `anthropic-key` and the
launcher can reuse a brokered Claude runtime grant. Otherwise Claude's own
upstream auth stays ambient while Ember still brokers the Git/GitHub/tool lane.
To switch later, rerun `ember init --for claude-code` with
`ANTHROPIC_API_KEY` exported or run `ember vault add --name anthropic-key`.

## 3. Confirm the daemon is up

```bash
ember status
```

`sudo ember daemon install` already bootstraps/enables the platform service. `ember status` is the simplest sanity check: confirm the daemon socket is up and the vault / persona state is visible.

Use `ember daemon start` only for manual foreground/dev starts.

## 4. Launch Claude Code through ember

```bash
ember claude-code
```

`ember init --for claude-code` creates or reuses the persona/grant surfaces it
needs and patches the Claude settings the launcher depends on. If the shadow
shims are missing, raw `gh` / `git` calls bypass the broker.

## 5. Check the audit surface after your first classified action

```bash
ember status
ember receipt list
```

The grant boundary only counts if you can see it. After the first brokered
action, the daemon should be emitting Receipts for credential-bearing actions
and state changes.

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
