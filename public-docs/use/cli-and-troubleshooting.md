# CLI and Troubleshooting

For the current pre-release surface, the top-level operator journey is:

1. `ember init --for claude`
2. `ember status`
3. `ember claude`

Everything else should support that journey, not compete with it.

For Codex users, the parallel advanced path is:

1. `codex login`
2. `ember init --for codex`
3. `ember status`
4. `ember codex`

## What to remember first

If you only remember one rule, make it this:

- start with `ember init --for claude`
- verify with `ember status`
- relaunch through `ember claude`

If you are using Codex, sign in with Codex first, then let `ember init --for
codex` import and broker runtime authority for the managed launcher.

## Headline commands

- `ember init`
- `ember status`
- `ember claude`
- `ember codex`
- `ember vault ...`
- `ember grant ...`
- `ember approval ...`
- `ember receipt ...`
- `ember audit ...`
- `ember version`

## First repair steps

If the installed path looks wrong, start here and in this order:

```bash
ember status
ember doctor
sudo ember daemon install
```

These are the primary repair entry points for the installed daemon posture.

## GitHub repair path

If the install looks healthy but GitHub authority is not ready, use:

```bash
ember github status --json
ember github setup
```

For the current App-first truth and degraded PAT boundary, see
[GitHub setup and auth](./github-setup-and-auth.md).

## After repair

Once the daemon and GitHub posture both look healthy, go back to:

```bash
ember claude
```

That is the supported managed launcher path. Do not switch to lower-level
foreground-daemon habits just because something broke once.

For Codex, go back to:

```bash
ember codex
```

If this fails before Emberlink session setup, check Codex native auth first and
then rerun `ember init --for codex`:

```bash
codex login
```

## What is intentionally not the primary docs story

The current public-friendly docs should not center:

- `ember daemon start`
- low-level broker commands
- partial recovery surfaces that are still internal or experimental
- old single-uid or manual foreground-daemon habits

The right public rule is: solve user jobs, not subsystem archaeology.

For the wider command contract, see the [CLI reference](../reference/cli-reference.md).
