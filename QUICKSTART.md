# Quickstart

<!-- QUICKSTART-future milestone -->

Get ember running in under 5 minutes.

## Prerequisites

- **Rust 1.75+** — install via [rustup.rs](https://rustup.rs)
- **Docker** (optional) — required only for `ember sandbox` commands; everything else works without it

## Install

```bash
cargo install --path crates/emberlink-cli --bin ember
```

> **macOS users downloading a release binary directly** (not via `cargo
> install`): macOS Gatekeeper attaches `com.apple.quarantine` to anything a
> browser writes, and on first launch shows *"Apple cannot verify that this
> app is free of malware."* The notarized `.pkg` from a tagged release does
> not have this problem; raw binaries pulled from the GitHub release page
> do. Clear the flag once with:
>
> ```bash
> xattr -d com.apple.quarantine ./ember
> ```
>
> Tracking proper notarization-of-raw-binaries as
> `future milestone` in `release-checklist`.

## Initialize

```bash
ember init --name "your-name"
```

On a new machine, `ember init` detects that the daemon service is not yet installed and shows a one-time prompt:

```
The ember daemon is not installed on this machine.

  The daemon is the trust broker that holds the vault encryption key,
  enforces grant policy, and signs Receipts for every agent action.
  Without it, `ember init` cannot open the vault or create a persona.

  Installing the daemon requires elevated privileges so it can create
  a dedicated `ember` service account and register a system service
  (LaunchDaemon on macOS, systemd unit on Linux). The command is:

      sudo ember daemon install

Run `sudo ember daemon install` now? [y/N]
```

Answer **y** to install the daemon automatically (requires `sudo`). Answer **n** to skip and install it manually later with `sudo ember daemon install`, then re-run `ember init`.

After the daemon is installed, `ember init` creates:
- Config file at `~/.ember/config.toml`
- Policy file at `~/.ember/policy.toml` (default rules)
- SQLite database at `~/.ember/data/daemon.db`
- Root persona (your identity)
- Vault encryption key stored in the OS keychain

Output shows each path and the keychain status. Ends with `Run \`ember daemon start\` to start the daemon.`

For scripted or CI provisioning, pass `--non-interactive` to skip the prompt and exit with an error if the daemon is not installed:

```bash
sudo ember daemon install
ember init --name "your-name" --non-interactive
```

## Start the daemon

### Separate-uid posture (recommended)

Install the daemon as a system service that runs under a dedicated `ember` service account. This is the production-grade posture (design): the kernel enforces the trust boundary between the agent process and the daemon, so the wedge claim "plaintext never enters the agent's process tree" holds unconditionally.

Works on macOS (LaunchDaemon under `ember` account) and Linux (systemd system unit under `ember` user):

```bash
ember daemon install-system
```

This writes the service file, creates the `ember` service account if absent, and starts the daemon. To remove:

```bash
ember daemon uninstall-system
```

### Single-uid posture (dev-only escape hatch)

> **Relaxed threat model.** The daemon runs as your own user. The architectural isolation claim is conditional — an adversary with code execution inside the agent process can ptrace or kill the daemon. Use this only for local development on a trusted machine.

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
- **Log**: `~/.ember/data/daemon.log`
- **PID**: process ID
- **Dashboard**: `http://localhost:3141` (browser UI; approve/deny/revoke require a CSRF token embedded in the page — curl-style POSTs from other origins are rejected)

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

## Mint a composite grant

A composite grant bundles multiple action scopes into one approval moment — one biometric tap, one durable trust artifact, one revocation point. Use this when your agent needs more than one credential class for a task (e.g., push code via `git.push` and deploy via `wrangler.deploy`).

```bash
ember grant create \
  --persona <persona-id> \
  --scope gh.pr_create,git.push,wrangler.deploy \
  --ttl 3600 \
  --label "release pipeline"
```

The full cohort-A scope menu — every action key, its biometric default, budget cap, and argv-redaction shape — is documented in:

- **`crates/core-storage/scope.example.toml`** — annotated copy-paste example
- **`docs/scope-toml-schema.md`** — schema reference for all cohort-A keys

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

**Success looks like:** `ember status` shows one persona (`coding-agent`), one active grant for `github-token`, and a recent `grant.created` audit event. The grant is time-bound — after the TTL expires, `ember status` shows it gone and `ember audit show` records its closure.

## Claude Code integration

`ember init --for claude-code` is a **required** prerequisite for any host running headless or a sequential Claude Code agent. It is the only step that installs the `~/.ember/shadow/` shim binaries, and without those shims raw `gh` / `git` / `kubectl` invocations bypass the broker entirely — every PR ships under your operator identity, and the audit trail collapses. See `future milestone` for the failure mode this prevents.

What the init does, in one shot: installs the `~/.claude/settings.json` `preToolUse` hook, drops shim binaries under `~/.ember/shadow/`, and registers `ember claude-code` as your launcher. After that, every classified action Claude Code attempts (`gh pr create`, `git push`, `kubectl apply`, …) routes through the daemon for grant resolution and signed Receipt emission.

**Verify after install:**

```bash
ls ~/.ember/shadow/gh ~/.ember/shadow/git
ensure_shadow_path_installed   # the assertion run by headless-preflight.sh
```

If the `ls` errors with `No such file or directory`, the shadow path is missing — re-run `ember init --for claude-code`. The `headless-preflight.sh` invariant check (see `.claude/scripts/headless-preflight.sh`) refuses to start the loop when the daemon is running but the shadow is absent, so the failure surfaces at session start rather than weeks later in a misattributed PR.

### 1. Start the daemon (required before cohort-A init)

<!-- daemon-before-cohort-a-init -->

The cohort-A init opens the vault to mint a 24h grant, which requires the daemon to be running. Start and install it as a persistent service first:

```bash
ember daemon start --background --install-agent
```

`--install-agent` writes a LaunchAgent (macOS) or systemd user unit (Linux) so the daemon survives reboot. Skip it if you only need a one-session daemon.

### 2. Run the cohort-A init

```bash
ember init --for claude-code
```

This is the cohort-A onboarding flow (separate from the generic `ember init --name <foo>`). It is idempotent — safe to re-run if you cancelled partway through.

> **Tip:** `ember init --for claude-code` now autostarts the daemon via `install-agent` if it detects the daemon is not running, so you can also run this as a single command — but starting the daemon explicitly first (step 1) is the recommended path and avoids a brief startup delay mid-init.

### 3. Verify hook injection

Confirm the daemon's `preToolUse` hook landed in your Claude Code settings:

```bash
grep -F 'preToolUse' ~/.claude/settings.json
```

You should see a `preToolUse` entry pointing at the ember daemon's classification gate. If it's missing, re-run step 2.

### 4. First-launch with `ember claude-code`

Relaunch your Claude Code session through the launcher:

```bash
ember claude-code
```

The launcher prepends `~/.ember/shadow/` to `PATH`, mints a session ID via the daemon, and exports it into the spawned Claude Code process. Inside that session, raw `gh` / `git` / `kubectl` invocations resolve to the corresponding ember Construct shims instead of the system binaries.

### 5. Block-and-poll approval flow

Pick a small real task ending in a classified action — `gh pr create`, `git push`, or similar. When Claude Code attempts it, the daemon blocks the call and surfaces a desktop notification + dashboard popup. Approve (or narrow the scope) from the dashboard and the action proceeds; the daemon emits a signed Receipt covering exactly what was authorized.

If you reject, the action fails closed and the rejection lands in the Receipt log too — both branches are auditable.

### 6. Inspect + export the Receipt

After the session, dump the Receipts for the operator's Touch-2 review:

```bash
ember receipt list                                                    # what got signed this session
ember receipt export --format md > /home/operator/tmp-example           # human-readable export
```

Send the markdown file back to the operator so they can verify the trust boundary held end-to-end.

### Advanced: MCP server mode

For programmable tool routing inside Claude Code (in addition to the launcher), the daemon also exposes an MCP server. This is optional — the launcher above handles the trust boundary on its own.

```bash
cargo install --path crates/emberlink-mcp --bin emberlink-mcp
```

Then add to `~/.claude/settings.json`:

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

With the daemon running, Claude Code gets MCP tools that route through the policy engine:
- `whoami` — get agent identity
- `list_grants` — list active grants
- `request_grant` — request a new grant (may require approval)
- `grant_status` — check grant status
- `use_credential` — use a credential via an active grant
- `list_receipts` — list signed Grant Receipts
- `get_receipt` — fetch a single Grant Receipt by ID
- `grant_budget_status` — live budget + runway for a composite grant

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

### Machine-readable status for scripting

Pass `--json` to get a single JSON object with all status fields:

```bash
ember status --json | jq .
```

This outputs `version`, `daemon` (running/pid/socket), `personas` count, `grants`, `approvals`, `standing_grants`, and `audit_events`. Useful for CI health checks and monitoring scripts.

### Daemon already running

```bash
ember daemon status
ember daemon stop && ember daemon start
```

**Keyring permission denied** — ember stores the vault encryption key in the OS keychain. On Linux, install `gnome-keyring` or `kwallet`, or run `ember daemon start` inside a desktop session.

**Docker not installed** — the sandbox commands require Docker. Install Docker Desktop (macOS/Windows) or Docker Engine (Linux). The rest of ember works without it; skip `ember sandbox create` if you don't need container isolation.

## Auto-start on login (single-uid, dev-only)

> **Relaxed threat model** — use `ember daemon install-system` for the separate-uid production posture.

Installs a per-user auto-start entry on macOS (LaunchAgent) and Linux (systemd user unit):

```bash
ember daemon install-agent
```

This writes and loads the service file, sets the correct binary path, and enables auto-restart on login. To remove:

```bash
ember daemon uninstall-agent
```

## Next steps

- **Configure grant conditions** — `ember policy show` to see active rules; `ember policy edit` to add rate limits, time windows, allowed-action lists.
- **Approval flow** — `ember grant approve` / `ember grant deny` for JIT escalation when an agent requests something outside its standing scope.
- **Policy reference** — `ember policy eval <action>` shows the deterministic decision the engine would make for a given action.
- **Architecture overview** — see `MANIFESTO.md` for the value thesis and `DESIGN.md` for the UX + architecture summary.

---

**The Grant Warden for AI agents.** [ember.link](https://ember.link)
