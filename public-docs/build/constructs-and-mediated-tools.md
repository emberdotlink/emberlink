# Constructs and Mediated Tools

Emberlink does not only ship a launcher and a daemon. It also ships
**Constructs**: mediated tool surfaces such as `ember-gh` and `ember-git`.

These are part of the current `v0.3.0` friendly-drop story. Additional
Constructs such as `ember-aws`, `ember-kubectl`, and other provider lanes are
experimental or in flight.

## What a Construct is

A Construct is a credential gate for a tool action.

It usually looks like a familiar command to the agent. The agent runs `gh` or
`git`. In a managed session, that command can resolve to an Emberlink-bundled
Construct that classifies the action and asks the daemon to resolve authority.

At a high level:

- the wrapper classifies the argv locally
- it asks the daemon to broker the action
- the daemon re-classifies the action server-side
- the daemon enforces the declared tool/action boundary before minting or
  injecting authority

The important truth is: the daemon remains the authority root. The Construct is
not a second trust root.

## Three Jobs of a Construct

A current Construct has three jobs:

| Job | Why it matters |
|---|---|
| Classify the action | Grants and receipts need stable action identities, not raw argv strings. |
| Declare the need | The daemon needs resource, scope, target, budget, runner, and materialization facts. |
| Carry the contract | Authority space needs structured facts before it can allow, prompt, narrow, or deny. |

Convenience is a side effect. The security model depends on those three jobs.

## Boundary Diagram

```text
agent space
  agent runs: gh pr create
       |
       v
Construct shim
  parses argv
  maps command to action
  sends execution contract
       |
       v
authority space
  emberd re-classifies
  evaluates grant and policy
  chooses materialization policy
       |
       v
execution space
  real tool runs with narrowed authority
  receipt and audit evidence are recorded
```

The shim is deliberately not trusted as the final authority. It is a carrier
for action intent and runtime context. `emberd` enforces.

## `gh pr create` as a Construct Action

A familiar command becomes a mediated action only after it has enough structure
to cross the daemon boundary.

```text
input argv
  gh pr create --title "..." --body "..."

local classification
  action: github.pull_request.create
  target: owner/repo from remote or --repo
  scope: pull-request write

execution contract
  workspace_ref
  runner_class
  materialization_policy
  grant need
  receipt facts

daemon decision
  allow, prompt, narrow, or deny
```

If a wrapper cannot explain the action and target in those terms, it should
fail closed or ask for a narrower path rather than broadening authority.

## Current public Construct cohort

The current public friendly-drop cohort is two end-to-end Constructs:

- `ember-gh`
- `ember-git`

Those are the tool surfaces that currently define the friendly operator story.

The daemon's internal broker registry is broader than this public cohort, but
the public docs should not imply that every broker-backed provider is already a
headline end-to-end user lane.

`ember-kubectl`, `ember-aws`, and additional provider/tool Constructs may exist
in code or development lanes, but they are not part of the validated `v0.3.0`
public proof surface.

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

The practical test is whether the receipt would be useful to a developer who
did not watch the session. "A shell command ran" is weak evidence. "Persona X
used grant Y to create a pull request in repo Z through runner R under policy
P" is the shape Emberlink is trying to preserve.

## Construct vs Raw Wrapper

A raw wrapper can hide a token from an environment variable. That is not enough
for Emberlink's model.

A Construct needs to answer:

- What action is this command attempting?
- What resource and scope does that action need?
- Which grant covers it?
- Which runner class executes it?
- How is authority materialized?
- What should the receipt prove?

If those questions are not answered, the wrapper may be useful, but it is not
yet carrying the full Construct model.

## Installed Name vs Artifact Name

The artifact name and the command name can differ.

For example, `ember-gh` is the Emberlink-bundled artifact. Inside the managed
tool path, the command a user or agent sees may still be `gh`.

That distinction keeps normal tool muscle memory while preserving the ability
to audit which mediated artifact actually carried the request.

## What this means in practice

If the managed path is healthy, users should prefer the mediated tools that the
launcher and install flow expect.

Examples:

- `ember init --for claude` plus `ember claude` is the current
  managed session path
- `ember init --for codex` plus `ember codex` is the supported advanced Codex
  launcher path
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
  public friendly-drop Constructs

## Builder Path

If you want to build your own Construct, start with the model before the file
format:

- [Current Primitives](../concepts/primitives.md)
- [Construct Authoring Model](./build-a-construct.md)

Construct authoring is Preview. The conceptual model is intentional, but the
third-party publishing and validation story is still settling.

## Related pages

- [Choose an integration surface](./choosing-an-integration-surface.md)
- [Construct Authoring Model](./build-a-construct.md)
- [MCP integration](./mcp-integration.md)
- [Architecture overview](../concepts/architecture.md)
