

> [!NOTE]
> Support level: **Supported**.
> Source truth: `docs/cli-reference.md`, `QUICKSTART.md`, `docs/current-architecture.md`.
# CLI and Troubleshooting

For the current pre-release surface, the top-level operator journey is:

1. `ember init --for claude`
2. `ember status`
3. `ember claude`

Everything else should support that journey, not compete with it.

## Headline commands

- `ember init`
- `ember status`
- `ember claude`
- `ember vault ...`
- `ember grant ...`
- `ember approval ...`
- `ember receipt ...`
- `ember audit ...`
- `ember version`

## First repair steps

If the installed path looks wrong, start here:

```bash
ember status
ember status --troubleshoot
sudo ember daemon install
```

These are the primary repair entry points for the installed daemon posture.

## GitHub repair path

If the install is healthy but GitHub authority is not ready, use:

```bash
ember github status --json
ember github setup
```

For the current App-first truth and degraded PAT boundary, see
[GitHub setup and auth](./github-setup-and-auth/).

## What is intentionally not the primary docs story

The current public-friendly docs should not center:

- `ember daemon start`
- low-level broker commands
- partial recovery surfaces that are still internal or experimental
- old single-uid or manual foreground-daemon habits

The right public rule is: solve user jobs, not subsystem archaeology.

For the wider command contract, see the [CLI reference](../reference/cli-reference/).
