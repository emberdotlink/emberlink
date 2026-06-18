# Quickstart

This is the canonical install and onboarding path for the current product surface.

The source mirror may be public before the first public supported build. Until
`v0.3.1`, treat this guide as the **current pre-release / friendly-preview
path**, not as a broad GA promise. The release boundary lives in
[support levels and release posture](public-docs/get-started/support-levels-and-release-posture.md).

## Prerequisites

- **Rust 1.96.0** if building from source — install via [rustup.rs](https://rustup.rs)
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
ember init --for claude
```

This is the load-bearing first-run path for friendly testers. It is
idempotent, wires the Claude Code shadow shims, and if the daemon is not yet
installed it offers to run `sudo ember daemon install` for you and then
resumes. The daemon runs under a dedicated `ember` service account; the old
single-uid / `install-system` split is retired.

Claude runtime auth is conditional, not magic. If `ANTHROPIC_API_KEY` is in
your environment when you run init, Ember stores it as `anthropic-key` and the
launcher can reuse a brokered Claude runtime grant. Otherwise Claude's own
upstream auth stays ambient while Ember still brokers the Git/GitHub/tool lane.
To switch later, rerun `ember init --for claude` with
`ANTHROPIC_API_KEY` exported or run `ember vault add --name anthropic-key`.
For high-value long-lived material, add `--require-biometric` so every future
read requires a fresh presence proof, for example
`ember vault add --name github/apps/<slug>/install-<id>/private-key --file ./private-key.pem --require-biometric`.

## 3. Confirm the daemon is up

```bash
ember status
```

`sudo ember daemon install` already bootstraps/enables the platform service. `ember status` is the simplest sanity check: confirm the daemon socket is up and the vault / persona state is visible.

Use `ember daemon start` only for manual foreground/dev starts.

## 4. Launch Claude Code through ember

```bash
ember claude
```

`ember init --for claude` creates or reuses the persona/grant surfaces it
needs and patches the Claude settings the launcher depends on. If the shadow
shims are missing, raw `gh` / `git` calls do not use broker mediation.

### Bare `claude` auto-routes through the broker

`ember dev install` (and the prod-equivalent install) writes a
`claude` shim in the operator-side shadow binary directory that exec's
`ember claude-code "$@"`.
Any shell with the ember shadow PATH prepended — every shell launched by
`ember claude-code` — picks up that shim, so typing plain `claude` lands
inside the brokered launcher rather than invoking the system Claude Code
binary directly. The shadow shim is unconditional and installed for every
operator.

Operators in shells outside an agent session (a plain `Terminal.app`
window, say) bypass the shadow PATH. To cover that case, the install
wizard prompts:

```text
Optional: add a bare-`claude` shell function to ~/.zshrc / ~/.bashrc?
```

Answering `y` appends a managed function block to your shell rc
files (default is `N` — declining leaves your rc files untouched). The
block reads:

```sh
# emberlink:claude-wrap-begin
claude() {
  if [ -n "${EMBER_NO_CLAUDE_WRAP:-}" ]; then
    command claude "$@"
  else
    ember claude-code "$@"
  fi
}
# emberlink:claude-wrap-end
```

#### Opting out

- **Session-local:** `export EMBER_NO_CLAUDE_WRAP=1` before launching
  Claude Code. The shadow shim and the shell function both honor this
  env var.
- **Permanent:** delete the managed Emberlink region from `~/.zshrc` /
  `~/.bashrc`. Re-running the install wizard re-prompts (it doesn't
  silently re-add the block once removed because the begin/end markers are gone).
- **Per-host:** delete the `claude` shim from the operator-side shadow binary
  directory (`~/Library/Application Support/Emberlink/shadow/bin/` on macOS,
  `$XDG_DATA_HOME/emberlink/shadow/bin/` on Linux) to opt out of the shim
  (the wizard will reinstall it on the next `ember dev install`).

Background: the hybrid (shadow shim + opt-in shell-init wrap) was chosen on
2026-05-15 after the gap analysis showed bare-`claude`
invocations were exactly how operators were bypassing the broker. The
shadow shim alone left non-agent shells uncovered; the shell wrap alone
left launcher-managed shells dependent on operator rc-file health. See
the public [CLI reference](public-docs/reference/cli-reference.md) for the
current operator contract.

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
      "args": ["--daemon-socket", "/Library/Application Support/Emberlink/run/daemon.sock"]
    }
  }
}
```

On Linux the daemon socket is at `/run/ember/daemon.sock`. These are the
current OS system locations; the legacy `~/.ember/run/daemon.sock` layout is
retired, and operators on pre-migration hosts should run
`sudo ember daemon migrate-paths-v1` first.

The launcher and the MCP server solve different layers: the launcher gives you the current host-side construct path; MCP exposes daemon tools directly.

## Troubleshooting

- **Daemon install issues:** re-run `sudo ember daemon install`; this is the canonical way to repair install posture drift.
- **Claude Code integration issues:** re-run `ember init --for claude` and confirm the operator-side shadow shim directory contains the expected shims. This is the operator-conventional path (`~/Library/Application Support/Emberlink/shadow/` on macOS, `$XDG_DATA_HOME/emberlink/shadow/` on Linux); the legacy `~/.ember/shadow/` layout is retired and the migration runner relocates it.
- **Architecture questions:** start with [Architecture overview](public-docs/concepts/architecture.md), then use [Grant Warden model](public-docs/concepts/grant-warden.md) and the relevant public reference page.

## Related docs

- [`README.md`](README.md) — overview
- [Architecture overview](public-docs/concepts/architecture.md) — compact current-state map
- [Grant Warden model](public-docs/concepts/grant-warden.md) — terminology and invariants
- [CLI reference](public-docs/reference/cli-reference.md) — current public operator contract
- [Support levels and release posture](public-docs/get-started/support-levels-and-release-posture.md) — support labels and release boundary
