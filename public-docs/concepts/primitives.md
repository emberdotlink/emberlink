# Current Primitives

Emberlink is easier to understand if you treat it as a small set of primitives
that compose.

This page covers the current public product concepts only. Broader target-state
vocabulary stays out of this guide until those surfaces are part of the public
contract.

The primitives answer five questions:

- Who is asking?
- What authority is being delegated?
- What action is being attempted?
- Where is authority materialized?
- What evidence proves the result?

## Map

```text
operator
  |
  | creates or approves
  v
grant envelope
  |
  +-- statement: resource + scope + budget
  |
  v
runtime persona attached to a session
  |
  | asks through launcher / Construct / MCP / SDK
  v
action + execution contract
  |
  | evaluated by emberd
  v
materialization policy + runner class
  |
  v
receipt + audit event
```

## One Action Through the Primitives

Use this table as the concrete version of the map. The example is an agent in
`ember claude` or `ember codex` attempting `gh pr create` inside a managed
workspace.

| Primitive | In the example |
|---|---|
| Principal | The operator identity that owns standing GitHub authority. |
| Persona | The delegated Emberlink identity used for the managed agent run. |
| Session | The live `ember claude` or `ember codex` run. |
| Attachment | The runtime binding between that session and persona. |
| Grant | The bounded authority allowing pull-request creation for one repository. |
| Statement | The grant line that binds GitHub repo target, pull-request write scope, budget, and expiry. |
| Construct | The Emberlink-bundled GitHub shim carrying `gh pr create` into the daemon boundary. |
| Action | `github.pull_request.create`. |
| Execution contract | The structured request containing action, target facts, workspace, runner, and materialization policy. |
| Runner class | Usually `local_trusted` for the current friendly path. |
| Materialization policy | Narrowed GitHub authority for this action, injected through the tool's native auth path. |
| Receipt | Signed evidence of the daemon decision, action, target, timing, and result. |

The names matter because each one gives you a different lever. You revoke a
grant, not a receipt. You inspect a receipt, not a grant. You debug a session
attachment differently from a missing scope.

## Principal and Persona

A **principal** is an entity that can hold authority.

A **persona** is the Emberlink identity used for delegation. The durable
persona is the long-lived identity. A runtime persona is the session-bound
identity that asks for authority during a live run.

Why this split matters:

- the durable persona can have grants, history, and revocation state
- the runtime persona can be bound to a process/session
- the daemon can ask, "is this the persona this process claims to be?"

## Daemon Host

The **daemon host** is the current custody boundary. `emberd` keeps custody of
standing credentials, grant state, receipt identity, and audit history.

Do not collapse host, persona, and session into one idea. They answer different
questions:

- host: where custody and daemon state live
- persona: who is delegated authority
- session: the current agent run asking for authority

## Session

A **session** is a live run of an agent or tool surface. `ember claude` and
`ember codex` open managed sessions. MCP and SDK integrations can also create
daemon-facing activity.

The session is not the authority model by itself. It is the runtime place where
a persona attaches and starts asking for actions.

## Grant

A **grant** is scoped, time-bound, revocable authority.

A useful grant says:

- who may use it
- what resource type it covers
- what scope is allowed
- what budget or usage limit applies
- when it expires
- whether further delegation is allowed

Agents should receive grants, not standing secrets.

## Statement

A **statement** is one line inside a grant envelope. It binds a resource type,
scope, and budget together.

Some grants can carry more than one statement. The envelope is one delegated
authority object; each statement is a specific bounded authority.

```text
grant envelope
  statement A: Credential + github:pull-request:write + 1 hour
```

## Resource and Scope

A **resource** is what authority applies to. In the current public product
story, the common resources are credential-backed tool actions, sessions, and
local execution surfaces.

A **scope** is what the delegated actor can do with that resource.

Keep these separate:

| Question | Primitive |
|---|---|
| What kind of thing is controlled? | Resource type |
| What may be done with it? | Scope |
| How much or how long? | Budget |
| Where is the value held? | Daemon host custody |

## Budget and Usage

A **budget** is the limit. **Usage** is what has been consumed.

Budgets can describe count, time, spend, rate, or another bounded quantity.
Usage gives the daemon and receipt layer a way to prove whether the delegated
actor stayed inside the grant.

## Construct

A **Construct** is a mediated execution surface for a credential-bearing tool.
The current `v0.3.0` public cohort includes `ember-gh` and `ember-git`.
Additional Constructs such as `ember-aws`, `ember-kubectl`, and other provider
lanes are experimental or in flight.

Inside a managed session, the installed name may be the familiar command
(`gh` or `git`) while the artifact is an Emberlink-bundled Construct. The point
is to preserve normal tool use while moving authority resolution into the
daemon.

See [Constructs and Mediated Tools](../build/constructs-and-mediated-tools.md).

## Action

An **action** is the classified thing the user or agent is trying to do.

Examples:

- create a GitHub pull request
- push to a protected remote
- read cluster state
- apply a Kubernetes manifest

Actions matter because grants should authorize meaningful operations, not raw
argv strings. The Construct may parse argv locally, but `emberd` re-classifies
server-side before enforcing policy.

## Execution Contract

An **execution contract** is the structured request that crosses from agent
space into authority space. It carries the action, workspace, runner class,
materialization policy, and related context the daemon needs to make a
decision.

The contract is how Emberlink avoids treating "a command string from an agent"
as enough evidence to release authority.

## Runner Class

A **runner class** describes where and how the action will execute. The current
local trusted runner is the main shipped path. Isolated/container execution is
real but Preview.

The runner class matters because the same action can have different risk
depending on whether it runs on the host, in an isolated container, or through
another controlled adapter.

## Materialization Policy

A **materialization policy** describes how authority appears for the action.

Examples:

- mint a short-lived token
- inject a credential through the target tool's native auth path
- project a narrowed environment into a runner
- deny materialization entirely

The important rule: materialized authority should be downhill from the grant.
The action receives only what it needs, when it needs it.

## Receipt

A **receipt** is signed evidence. It records the relevant grant, action, time,
daemon root, and result so the action can be inspected later.

Receipts are not just logs. They are portable artifacts intended for offline
verification.

See [Receipts and Audit](./receipts-and-audit.md).

## Attachment and Standing Grant

An **attachment** binds a runtime persona to an active session or process.

A **standing grant** is reusable delegated authority that can be attached to a
session under policy. Standing grants are useful, but they need sharper
boundaries than raw standing credentials. Emberlink's job is to make those
boundaries explicit.

## Approval

An **approval** connects a human decision to the action it approved, denied, or
narrowed.

This matters because "the user clicked approve once" is not enough. The
approval must refer to a specific need, scope, and runtime context.

## Common Confusions

| Do not confuse | Why |
|---|---|
| Secret with grant | A secret is credential material. A grant is delegated authority. |
| Grant with receipt | A grant authorizes. A receipt proves what happened. |
| Session with persona | A session is a live run. A persona is the delegated identity. |
| Construct with daemon | A Construct carries and classifies a request. The daemon is the authority root. |
| Scope with custody | Scope says what can be done. Custody says where sensitive value is held today: the daemon host. |
| MCP with Construct | MCP exposes daemon tools. Constructs mediate credential-bearing command execution. |

## How to Use This Page

When designing your own integration, write down:

1. Which persona is asking?
2. Which action is being attempted?
3. Which resource and scope does the action need?
4. Which runner class will execute it?
5. How should authority be materialized?
6. What must the receipt prove?

If those answers are clear, you are thinking in Emberlink's model.
