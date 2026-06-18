# Construct Authoring Model

This page teaches the current Construct model behind Emberlink's bundled
mediated tools. It is not yet a stable third-party publishing contract.

Use it when you are trying to understand how a credential-bearing tool becomes
an Emberlink-mediated action surface.

## Support Boundary

Construct authoring is **Preview**.

The core model is intentional:

- classify a tool invocation into an action
- declare the authority that action needs
- send an execution contract to `emberd`
- let the daemon evaluate grant and policy
- materialize narrowed authority
- run through a runner class
- record receipt and audit evidence

The current public surface documents the model, not a supported external
publishing workflow. The public authoring, validation, and distribution story is
still settling. Do not assume a local prototype is ready to publish as a
supported third-party Construct.

## The Builder Question

Start with one sentence:

> This Construct lets an agent perform `<action>` against `<resource>` using
> `<scope>`, with authority materialized by `<policy>`, and evidence recorded
> as `<receipt claim>`.

If you cannot write that sentence, you are not ready to write the shim.

## Minimum Design Sheet

Before code, write a small design sheet for one action:

| Field | Example |
|---|---|
| Tool boundary | `gh` pull-request commands |
| Action identity | `github.pull_request.create` |
| Target facts | owner, repo, remote, branch, workspace |
| Resource | GitHub repository authority |
| Scope | pull-request write |
| Budget | one action, time window, or count limit |
| Runner class | `local_trusted` for the current friendly path |
| Materialization | narrowed GitHub authority through native `gh` auth path |
| Deny cases | missing target, repo mismatch, expired grant, unsupported argv |
| Receipt claim | persona, grant, repo, action, decision, runner, result |

That sheet is not ceremony. It is how you find the security boundary before
the implementation hides it in parsing code.

## Anatomy

```text
tool command
  |
  v
argv parser
  |
  v
action classifier
  |
  v
need declaration
  |
  v
execution contract
  |
  v
daemon decision
  |
  +--> deny
  +--> prompt / narrow
  +--> allow
         |
         v
materialization
  |
  v
runner
  |
  v
receipt claim
```

## 1. Choose the Tool Boundary

Pick a narrow credential-bearing tool boundary. Good candidates are tools where
authority matters:

- repository mutation
- deployment
- package publishing
- cloud resource mutation
- payment or billing mutation
- production data access

Do not wrap every binary on a PATH just to create a catalog. Emberlink should
mediate the actions where authority and accountability matter.

## 2. Define Actions

An action is a meaningful operation, not just a command string.

Good action names describe what is being attempted:

- `github.pull_request.create`
- `git.remote.push`
- `kubernetes.manifest.apply`
- `package.publish`

Avoid action names that merely restate argv:

- `run_command`
- `execute`
- `shell`
- `tool_call`

The daemon needs a stable action identity so grants, approvals, receipts, and
audit history can be understood later.

## 3. Declare the Need

For each action, write the need:

| Field | Question |
|---|---|
| Resource type | What kind of authority is controlled? |
| Scope | What may be done? |
| Target | Which repo, remote, cluster, package, account, or environment? |
| Budget | How much, how often, or how long? |
| Runner class | Where will the action execute? |
| Materialization policy | How should authority appear for the action? |

This is where the Construct becomes an authority surface rather than a wrapper.

## 4. Extract Targets

Most useful Constructs need target extraction.

Examples:

- GitHub repo from remote URL or `--repo`
- Git remote and branch from argv and workspace
- Kubernetes context, namespace, and resource kind
- package name and registry

Target extraction should be deterministic enough that the daemon can re-check
the result. If the target cannot be determined, fail closed or prompt instead
of widening authority.

## 5. Send an Execution Contract

The execution contract is the structured request to authority space. It should
carry:

- action id
- workspace reference
- runner class
- target facts
- materialization policy
- requested grant need
- audit facts needed for the receipt

The agent's raw command is not enough. The daemon needs the structured facts
that make the authority decision reproducible and auditable.

## 6. Materialize Downhill

Materialized authority should be no broader than the grant allows.

Examples:

- a short-lived GitHub token for one repo action
- a narrowed kubeconfig for a namespace-bound action
- an environment projection limited to the target tool
- no materialization when the action is denied or requires approval

If the only way to make the tool work is to release a long-lived broad secret
to the agent process, the Construct is not preserving Emberlink's security
model.

## 7. Record Receipt Claims

Before you write code, decide what the receipt must prove.

Useful receipt facts include:

- action id
- persona id
- grant id
- target resource
- runner class
- materialization policy
- decision outcome
- time bounds
- resulting command or provider operation

Receipts should be legible to someone who was not watching the original
session.

## Illustrative Shape

The exact manifest schema is still settling. Treat this as a model sketch, not
a copy/paste contract:

```toml
[construct]
name = "example-publisher"
version = "0.1.0"

[[actions]]
id = "package.publish"
argv_pattern = ["publish"]
resource_type = "Credential"
scope = "package:publish"
target_from = "package_manifest.name"
runner_class = "local_trusted"
materialization = "short_lived_registry_token"
receipt_claims = ["package", "registry", "version"]
```

The important part is not this syntax. The important part is the shape:
action, need, target, runner, materialization, evidence.

## Current Contract Terms to Keep Stable

Even while authoring remains Preview, use the current vocabulary consistently:

| Term | Use it for |
|---|---|
| action | the meaningful operation, such as `github.pull_request.create` |
| action reference | the structured identity for that operation |
| grant need | the authority required by the action |
| execution contract | the request crossing into authority space |
| runner class | where execution will happen |
| materialization policy | how narrowed authority appears for execution |
| receipt claim | what evidence must survive |

Avoid inventing synonyms in your docs or code comments. The terms line up with
the daemon model, the receipt story, and the support labels used across the
public docs.

## Test Matrix

A Construct is not ready until these cases are boring:

- allowed action succeeds with narrowed authority
- unsupported argv fails closed
- target mismatch is denied
- expired grant is denied
- over-budget grant is denied
- approval-required action prompts or queues
- daemon-side re-classification catches a shim-side mismatch
- receipt includes the target and decision facts
- raw underlying tool cannot accidentally bypass the managed session path

## Common Mistakes

- wrapping a tool without modeling actions
- using broad scopes because target extraction is hard
- trusting only shim-side parsing
- treating PATH shadowing as the security boundary
- releasing standing credentials into agent space
- recording a receipt that proves only "a command ran"
- claiming support for third-party publishing before validation is stable

## Where This Fits

If you are building an agent integration, you may not need a Construct. Use:

- [Choose an Integration Surface](./choosing-an-integration-surface.md) to pick
  the right lane.
- [MCP Integration](./mcp-integration.md) if your environment already speaks
  MCP.
- [TypeScript SDK](../experimental/sdk-typescript.md) or
  [Python SDK](../experimental/sdk-python.md) for experimental programmatic
  clients.

Use the Construct model when the core problem is credential-bearing command
execution and you need action-time authority mediation around an existing tool.
