# Install and First Run

If you are trying Ember for the first time, this is the shortest truthful path
to a working managed session:

1. Install `ember`
2. Run `ember init --for claude` for the headline path
3. Let the installer repair or provision the daemon if needed
4. Confirm health with `ember status`
5. Launch a managed session with `ember claude`

Codex is also supported as an advanced launcher path. If Codex is your agent
surface, use `codex login`, then `ember init --for codex`, then `ember codex`.

## Install

If you are in the named friendly cohort, use the signed preview artifact
distributed with your invite.

## Prerequisites

If you are using the signed preview artifact, you only need `ember` on your
`PATH`.

If you are building from the public source mirror, install:

- Rust 1.96.0 through `rustup`
- Git

Docker is optional. It is required only for `ember sandbox ...`.

If you are using Codex, install and authenticate Codex before the Emberlink
Codex path:

```bash
codex login
```

If you are evaluating from the public source mirror, use the source-build path:

```bash
git clone https://github.com/emberdotlink/emberlink.git
cd emberlink
cargo install --locked --path crates/emberlink-cli --bin ember
```

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

## Codex path

Use this path when Codex is the agent you intend to run:

```bash
codex login
ember init --for codex
ember status
ember codex
```

Codex starts from Codex's native login contract. Emberlink does not replace the
provider sign-in flow; during `ember init --for codex`, it can import local
Codex auth material with operator consent and refresh the brokered runtime
grant used by managed Codex sessions.

This is a supported advanced path, not the primary friendly onboarding lane. If
you are evaluating Emberlink without a Codex-specific need, start with
`ember init --for claude`.

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

If Claude runtime auth was already present during `ember init --for claude`,
Ember can reuse a brokered Claude runtime grant. Otherwise Claude's own
upstream auth remains ambient while Ember still brokers the Git/GitHub/tool
lane.

For Codex:

```bash
ember codex
```

If Codex has not been authenticated through its native CLI, fix that first with
`codex login`.

## Prove the boundary

After your first brokered tool action, check that Emberlink emitted evidence:

```bash
ember status
ember receipt list
ember audit query
```

If there are no receipts yet, make sure you launched through `ember claude` or
`ember codex` and that the action used a mediated tool path such as `gh` or
`git` inside the managed session.
