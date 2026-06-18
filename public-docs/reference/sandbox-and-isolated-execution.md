# Sandbox and Isolated Execution

Emberlink exposes a real `ember sandbox ...` surface for managed isolated
execution, but it is still an **advanced preview workflow**, not the main
operator story.

## Current public truth

Today the truthful sandbox contract is:

- regular sandbox CRUD and exec are real
- the daemon owns the sandbox metadata and the broker/grant orchestration path
- Docker is required for the current sandbox lane
- `sandbox run` is still split at the final interactive handoff

That means the sandbox surface is useful and real, but not as settled as the
main launcher path.

## Commands that are real today

### Sandbox lifecycle

```bash
ember sandbox create <name>
ember sandbox list
ember sandbox stop <id-or-name>
ember sandbox delete <id-or-name>
```

These commands are part of the current daemon-backed sandbox surface.

### Execute inside a sandbox

```bash
ember sandbox exec <id-or-name> -- <command...>
```

Use this when you already have a sandbox and want to run a command inside it.

### Start a new sandboxed run

```bash
ember sandbox run <name> --prompt "..."
```

This is the higher-level workflow path, but it has an important honesty
boundary:

- the daemon owns the sandbox-create/start and composite-grant
  policy/approval/orchestration half
- the final local `docker exec` handoff is still not fully daemon-owned

So `sandbox run` is real, but the end-to-end execution story is still more
mixed than the simpler CRUD/exec verbs.

## Prerequisite

For the current public contract, Docker is only required for sandbox commands.

If you are just evaluating the main launcher path, you do not need Docker.

## What this surface is for

Use sandboxes when you want:

- an isolated execution environment tied to Emberlink authority mediation
- a daemon-aware workflow surface beyond the main local launcher path
- a place to run advanced or experimental isolated tasks

## What this surface is not

Do not read the current sandbox docs as a promise that:

- every container/SCION path is equally shipped
- the whole final prompt/exec handoff is already daemon-owned
- sandbox is the main beginner path for Emberlink

The current public story is narrower than that. Start with `ember claude` or
the advanced `ember codex` launcher path before treating sandbox as the default
beginner workflow.

## Related pages

- [CLI reference](./cli-reference.md)
- [Install and first run](../get-started/install-and-first-run.md)
- [Architecture overview](../concepts/architecture.md)
