

> [!NOTE]
> Support level: **Supported**. Reviewed: 2026-06-17. Status: current.

# Install and First Run

If you are trying Ember for the first time, this is the shortest truthful path
to a working managed Claude session:

1. Install `ember`
2. Run `ember init --for claude`
3. Let the installer repair or provision the daemon if needed
4. Confirm health with `ember status`
5. Launch a managed session with `ember claude`

## Install

If you are in the named friendly cohort, use the signed preview artifact
distributed with your invite.

If you are evaluating from the public source mirror, use the source-build path:

```bash
git clone https://github.com/emberdotlink/emberlink.git
cd emberlink
cargo install --locked --path crates/emberlink-cli --bin ember
```

You do not need Docker for this path. Docker matters only for
`ember sandbox ...`.

## Run the canonical onboarding flow

```bash
ember init --for claude
```

This is the load-bearing first-run path. It:

- wires the Claude Code shadow shims
- creates or reuses the managed persona and grant surfaces
- offers to run `sudo ember daemon install` if the daemon-backed path is not
  ready yet

Use this before you reach for lower-level daemon or launcher commands.

## Confirm the daemon is healthy

```bash
ember status
```

On the installed path, `ember status` is the first support/debug checkpoint.
Use it before you start chasing lower-level commands.

## Launch a managed session

```bash
ember claude
```

This is the supported managed launcher path.

If `ANTHROPIC_API_KEY` was present during `ember init --for claude`,
Ember can reuse a brokered Claude runtime grant. Otherwise Claude's own
upstream auth remains ambient while Ember still brokers the Git/GitHub/tool
lane.
