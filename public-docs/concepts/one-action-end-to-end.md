# One Action End to End

This page follows one current action through Emberlink:

> an agent in a managed session runs `gh pr create`.

The exact provider mechanism can vary by setup. For GitHub, GitHub App
mediation is the preferred lane; PAT-backed fallback can exist in degraded
configurations. The model is the same: the agent asks for a GitHub action,
`emberd` decides whether authority may be released, and the receipt records
what happened.

## The Shape

```text
operator
  |
  | approves bounded GitHub authority
  v
emberd
  |
  | opens managed session
  v
agent space
  |
  | gh pr create
  v
Construct shim
  |
  | action + execution contract
  v
authority space
  |
  | grant check, policy check, materialization decision
  v
execution space
  |
  | real gh runs with narrowed authority
  v
receipt + audit evidence
```

Read that diagram left to right. The agent does not become the authority root.
The agent asks. The daemon decides. The runner executes with materialized
authority. The receipt is the artifact that survives.

## 1. Start Inside a Managed Session

The supported beginner path uses Claude Code:

```bash
ember init --for claude
ember claude
```

The supported advanced Codex path starts from Codex's native login and then
lets Emberlink import and broker runtime authority with operator consent:

```bash
codex login
ember init --for codex
ember codex
```

The launcher matters because it gives `emberd` a session to bind. A raw shell
with the same binary on `PATH` is not equivalent to a managed session.

## 2. Attach Runtime Authority

At runtime, the daemon has to answer two separate questions:

| Question | Current primitive |
|---|---|
| Who is this live caller? | runtime persona + attachment |
| What may this caller do? | grant + statements |
| How is the request bounded? | resource, scope, target, budget, expiry |
| Where may it run? | runner class |
| How may authority appear? | materialization policy |

A grant is not a token. It is the daemon's current authority envelope for a
persona, action need, target, and limit.

## 3. The Agent Runs the Familiar Command

Inside the managed session, the agent may type the normal command:

```bash
gh pr create --title "docs: clarify authority model" --body "..."
```

The command name is familiar, but the path can resolve to the Emberlink-bundled
GitHub Construct. The Construct is the credential gate for this command lane.
It parses the invocation, extracts target facts, and carries action intent to
the daemon.

For this example, the action is:

```text
github.pull_request.create
```

The useful target facts include the repository, branch, remote, workspace, and
whether the operation needs write authority.

## 4. The Construct Carries an Execution Contract

The Construct does not ask the daemon for "some GitHub token." It sends a
structured request.

```text
execution contract
  action_ref: github.pull_request.create
  workspace_ref: current managed workspace
  target: github repo + remote + branch facts
  runner_class: local_trusted
  materialization_policy: narrowed GitHub authority for this action
  need: pull-request write authority for the target repo
  audit_facts: argv classification, target facts, caller/session context
```

The exact carrier fields are implementation details. The boundary is the
important part: agent space sends a structured action request to authority
space. A command string alone is not enough to release authority.

## 5. `emberd` Re-Classifies and Decides

The daemon does not blindly trust shim-side parsing. It re-classifies the
request and evaluates policy:

- Does the runtime attachment belong to the claimed persona?
- Does an active grant cover `github.pull_request.create`?
- Does the grant cover this repository and scope?
- Is the requested runner class allowed?
- Is the budget still available?
- Is the grant expired or revoked?
- Does this action require a prompt or narrowed approval?

The decision is one of four outcomes:

| Outcome | Meaning |
|---|---|
| Allow | The grant and policy cover the request. |
| Prompt | A human decision is required before authority is released. |
| Narrow | The request can proceed only with a smaller target, scope, or budget. |
| Deny | The request is outside current authority. |

This is the core Warden move: `need <= grant`. The daemon should only
materialize authority that is downhill from the approved grant.

## 6. Authority Is Materialized for the Action

If the daemon allows the request, it materializes authority for the action.

![A standing credential stays with emberd, a grant bounds the requested action, narrowed authority is materialized for execution, and receipt evidence survives](../assets/diagrams/authority-lifecycle.svg)

For GitHub, that may be a short-lived provider token or other narrowed
provider-native authorization. The materialized authority is injected through
the target tool's native auth path for the duration and shape of the action.

The standing credential remains in authority space. The agent should not need
to read or copy it.

```text
standing credential
  custody: emberd

materialized authority
  audience: target tool/action
  scope: repo + pull-request write need
  lifetime: bounded by grant and provider contract
  evidence: audit event + receipt fields
```

## 7. The Real Tool Runs

Execution happens in the selected runner class. The current main shipped path
is the local trusted runner. Isolated/container execution is real but Preview,
and it has a separate support boundary.

In the local trusted path, Emberlink moves credential release and action
evidence into the daemon boundary. It does not claim that the whole host has no
ambient authority. If your host shell already has a raw GitHub token, a raw
tool outside the managed path can still use that ambient authority.

## 8. Evidence Survives the Session

After the action, you should be able to inspect evidence:

```bash
ember receipt list
ember receipt show <id>
ember receipt verify <path-or-id>
ember audit query
```

The receipt should be legible after the transcript is gone. It should identify
the daemon identity, persona, grant, action, target, time bounds, decision, and
result facts needed to explain the delegated action.

The audit stream is the local event history. The receipt is the portable proof
object.

## What You Should Learn From This

This is not "wrap `gh` and hide a token."

The model is:

```text
tool action
  -> declared need
  -> execution contract
  -> daemon decision
  -> materialized authority
  -> runner execution
  -> receipt evidence
```

Once that shape is clear, you can reason about every Emberlink surface:

- A Construct is the right lane when the problem is credential-bearing command
  execution around an existing tool.
- MCP is the right lane when an MCP-capable environment should call daemon
  tools directly.
- An SDK is the right lane when your own program wants to integrate with the
  daemon model. SDKs are Experimental.

## Debug the Example

| Symptom | First place to look |
|---|---|
| `gh` bypasses mediation | managed session setup and shim path |
| daemon denies the request | grant target, scope, expiry, budget, or runner class |
| prompt appears unexpectedly | approval policy or missing standing grant attachment |
| action succeeds but no receipt appears | whether the mediated path was actually used |
| receipt lacks useful target facts | Construct classification and audit facts |
| Codex path asks for Codex auth | expected: sign in with Codex first, then rerun `ember init --for codex` so Emberlink can import and broker runtime authority |

The fastest way to understand Emberlink is to trace one action until every row
in that table has a concrete answer.

## Next Pages

- [Current Primitives](./primitives.md)
- [Runtime Flow](./runtime-flow.md)
- [Security Model](./security-model.md)
- [Constructs and Mediated Tools](../build/constructs-and-mediated-tools.md)
