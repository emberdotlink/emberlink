

> [!NOTE]
> Support level: **Supported**.
> Source truth: `docs/cli-reference.md`, `QUICKSTART.md`, `docs/current-architecture.md`.
# CLI Reference

The current public Ember CLI contract is intentionally narrower than the full
binary surface. The user story is:

1. `ember init --for claude-code`
2. `ember status`
3. `ember claude-code`

Everything else should support that journey, not compete with it.

For the core delegated-authority surface beyond that top-level flow, see
[Grants and approvals](./grants-and-approvals/).

## Primary commands

These commands define the current public-friendly operator surface:

- `ember init`
- `ember uninstall --for claude-code`
- `ember status`
- `ember claude-code`
- `ember vault ...`
- `ember grant ...`
- `ember approval ...`
- `ember receipt ...`
- `ember audit ...`
- `ember version`

## Advanced but supported commands

These are real supported surfaces, but they are task-specific rather than the
headline journey:

- `ember daemon ...` for install, reload, and repair
- `ember persona ...` for advanced persona management
- `ember config ...` for resolved-config inspection
- `ember github ...` for GitHub App setup and GitHub authority posture
- `ember trust ...` for trust and verification-chain inspection
- `ember sandbox ...` for managed isolated execution

## Real but still preview commands

These command groups exist, but they should not be read as equally settled with
the main supported operator lane:

- `ember headless ...` for unattended delegation and advanced preview flows

## Commands that should not anchor public docs

Do not teach these as the main operator path:

- `ember daemon start`
- low-level broker issuance flows
- manual foreground-daemon habits
- internal or development-only command groups such as `ember dev ...`,
  `ember demo ...`, `ember bridge ...`, or `ember orchestrator ...`

## GitHub truth

The current GitHub story is:

- App-first through `ember github setup`
- the public App manifest/install URL is real, but not a self-sufficient local
  path by itself
- `github-pat` is degraded fallback only, not an equal-security lane

If you are trying to repair a GitHub authority issue, start with:

```bash
ember github status --json
ember github setup
ember status --troubleshoot
```

For the read-only trust inspection surface, see
[Trust and verification](./trust-and-verification/).

For the current sandbox contract and Docker boundary, see
[Sandbox and isolated execution](./sandbox-and-isolated-execution/).

