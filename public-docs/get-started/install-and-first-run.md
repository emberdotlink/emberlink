

> [!NOTE]
> Support level: **Supported**.
> Source truth: `QUICKSTART.md`, `README.md`, `docs/cli-reference.md`.
# Install and First Run

The current canonical onboarding flow is:

1. Install `ember`
2. Run `ember init --for claude-code`
3. Let the installer repair or provision the daemon if needed
4. Confirm health with `ember status`
5. Launch a managed session with `ember claude-code`

## Install

If you are in the named friendly cohort, use the signed preview artifact
distributed with your invite.

If you are evaluating from the public source mirror, use the source-build path:

```bash
git clone https://github.com/emberdotlink/emberlink.git
cd emberlink
cargo install --locked --path crates/emberlink-cli --bin ember
```

## Run the canonical onboarding flow

```bash
ember init --for claude-code
```

This is the load-bearing first-run path. It wires the Claude Code shadow shims
and, if needed, offers to run `sudo ember daemon install` before resuming the
rest of onboarding.

## Confirm the daemon is healthy

```bash
ember status
```

On the installed path, `ember status` is the first support/debug checkpoint.
Use it before you start chasing lower-level commands.

## Launch a managed session

```bash
ember claude-code
```

If `ANTHROPIC_API_KEY` was present during `ember init --for claude-code`,
Ember can reuse a brokered Claude runtime grant. Otherwise Claude's own
upstream auth remains ambient while Ember still brokers the Git/GitHub/tool
lane.

