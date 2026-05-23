

> [!NOTE]
> Support level: **Preview**.
> Source truth: `README.md`, `QUICKSTART.md`, `docs/current-architecture.md`, `docs/cli-reference.md`.
# Constructs and Mediated Tools

Emberlink does not only ship a launcher and a daemon. It also ships
**Constructs**: mediated tool surfaces like `ember-gh`, `ember-git`, and
`ember-kubectl`.

These are part of the current public friendly-drop story.

## What a Construct is

A Construct is a PATH-shadowed tool wrapper that sits between the user or agent
and the underlying credentialed action.

At a high level:

- the wrapper classifies the argv locally
- it asks the daemon to broker the action
- the daemon re-classifies the action server-side
- the daemon enforces the declared tool/action boundary before minting or
  injecting authority

The important truth is: the daemon remains the authority root. The Construct is
not a second trust root.

## Current public Construct cohort

The current public friendly-drop cohort is three end-to-end Constructs:

- `ember-gh`
- `ember-git`
- `ember-kubectl`

Those are the tool surfaces that currently define the friendly operator story.

The daemon's internal broker registry is broader than this public cohort, but
the public docs should not imply that every broker-backed provider is already a
headline end-to-end user lane.

## What the daemon enforces

For mediated tool execution, the daemon is doing real gatekeeping work:

- action declaration from `construct.toml`
- daemon-side re-classification instead of trusting the shim blindly
- env passthrough filtering
- binary pin / bundled-binary checks
- git remote binding checks where applicable
- scoped credential mint and inject
- audit and receipt emission around the mediated action

That is why these wrappers matter. They are not just convenience aliases.

## What this means in practice

If the managed path is healthy, users should prefer the mediated tools that the
launcher and install flow expect.

Examples:

- `ember init --for claude` plus `ember claude` is the current
  managed session path
- inside that session, the mediated tool lane is what keeps Git/GitHub tool use
  inside the daemon-brokered boundary

If the PATH-shadowed shims are missing or bypassed, raw tool calls can escape
the intended mediation story.

## What not to assume

Do not assume:

- every command-line tool on your host is automatically mediated
- Constructs are interchangeable with MCP
- Constructs are a replacement for the daemon
- every advanced provider or headless lane has the same support posture as the
  three public friendly-drop Constructs

## Related pages

- [Choose an integration surface](./choosing-an-integration-surface/)
- [MCP integration](./mcp-integration/)
- [Architecture overview](../concepts/architecture/)
