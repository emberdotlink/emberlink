# Runtime Flow

This page follows one managed session from launch to evidence.

The exact agent surface can vary. The current friendly path is
`ember claude`. `ember codex` is also supported for advanced users, with Codex
starting from Codex's native login path before Emberlink imports and brokers
runtime authority with operator consent. MCP and SDK paths use the same daemon
authority model through different adapters.

## One Session

```text
operator
  |
  | ember init --for claude        or        ember init --for codex
  v
managed configuration
  |
  | ember claude                   or        ember codex
  v
session registration
  |
  v
runtime persona + attachment
  |
  v
agent attempts sensitive action
  |
  +--> Construct path: gh / git
  |
  +--> MCP path: daemon tool request
  |
  +--> SDK path: programmatic daemon request
  |
  v
emberd evaluates grant + policy + action
  |
  +--> deny
  +--> prompt / narrow
  +--> allow and materialize authority
               |
               v
          action executes
               |
               v
          receipt + audit event
```

## What Crosses Each Boundary

The flow is easier to debug if you name what crosses each boundary.

| Boundary | What crosses | What should not cross |
|---|---|---|
| launcher to daemon | session registration, workspace facts, runtime binding | a claim that the launcher itself is the authority root |
| agent to Construct | familiar argv and process context | standing credentials |
| Construct to daemon | action identity, target facts, execution contract | unstructured "please give me a token" requests |
| daemon to runner/tool | materialized authority shaped by grant and policy | broad long-lived custody secrets |
| daemon to evidence | receipt and audit facts | transcript-only proof |

Those crossings are the product shape. When something fails, ask which
boundary failed before changing credentials or widening grants.

## Step 1: Initialize

Initialization sets up the local operator posture. For the current headline
path:

```bash
ember init --for claude
```

For Codex:

```bash
codex login
ember init --for codex
```

Codex starts from Codex's native login flow. During `ember init --for codex`,
Emberlink can import the local auth material with operator consent and refresh
the brokered runtime grant used by managed Codex sessions.

## Step 2: Launch

The launcher opens a managed session:

```bash
ember claude
```

or:

```bash
ember codex
```

The launcher is not the whole architecture. Its job is to create a known
runtime envelope so the daemon can bind a session, persona, workspace, and
authority posture together.

## Step 3: Attach Runtime Persona

The daemon must know which runtime persona is asking. Emberlink's model splits
two questions:

- What is this persona allowed to do?
- Is this process really the runtime asking as that persona?

The first question is answered by grants and policy. The second is answered by
runtime binding, not by giving the process a bearer token that says "trust me."

## Step 4: Classify the Action

When the agent tries a sensitive operation, the request needs to become an
action.

For a Construct-mediated command, the Construct parses argv and identifies an
action such as "create pull request" or "push to remote." The daemon then
re-classifies server-side before trusting the result.

For MCP or SDK flows, the caller sends a structured daemon request instead of a
shadowed command invocation.

## Step 5: Evaluate Grant and Policy

The daemon compares the requested action with available authority:

- Does an attached grant cover this resource and scope?
- Is the budget still available?
- Does the runner class match policy?
- Is the workspace or target allowed?
- Does this action require human approval?

The outcome is allow, prompt, narrow, or deny.

## Step 6: Materialize Authority

If allowed, the daemon materializes only the authority required for the action.
That may mean minting a short-lived token, injecting authority through a tool's
native auth path, or preparing a narrowed execution environment.

The agent should not receive the standing credential. The action receives the
minimum authority needed to run.

For GitHub actions, GitHub App mediation is the preferred current lane. A
PAT-backed fallback can exist where configured, but it is a degraded posture
compared with provider-native narrowed mediation.

## Step 7: Execute

Execution happens in the selected runner class. The current local trusted runner
is the main shipped path. Isolated execution exists as Preview and has its own
support boundary.

See [Sandbox and Isolated Execution](../reference/sandbox-and-isolated-execution.md).

The local trusted runner preserves normal host tool behavior. It does not erase
ambient host authority outside the managed path. If a raw `gh` or `git` command
bypasses the mediated shim and already has credentials, that is outside the
intended Construct lane.

## Step 8: Record Evidence

The daemon records audit events and receipt evidence around the decision and
action. A receipt is the portable proof object. The audit log is the local event
history.

```bash
ember receipt list
ember receipt show <id>
ember receipt verify <path-or-id>
ember audit query
```

## What to Debug First

When the flow fails, debug in this order:

1. Is the daemon healthy? Run `ember status`.
2. Is the launcher path the intended one? Use `ember claude` or `ember codex`,
   not a raw agent process.
3. Is the mediated tool path active? Check that the managed session sees the
   expected `gh` or `git` shim.
4. Does a grant cover the requested action?
5. Did the daemon deny, prompt, or narrow the request?
6. Is there receipt or audit evidence explaining the result?

That order keeps you on the product path instead of falling into subsystem
archaeology.

## Read the Flow as a Builder

If you are building an integration, map your design onto the same flow before
writing code:

| Question | Builder answer |
|---|---|
| What action is attempted? | Give it a stable action identity. |
| What authority does it need? | Declare resource, scope, target, and budget. |
| How does it reach `emberd`? | Choose Construct, MCP, or SDK. |
| Where does it run? | Pick the runner class and support level honestly. |
| How is authority materialized? | Keep it downhill from the grant. |
| What evidence remains? | Decide the receipt facts before implementation. |

If the answer to any row is "the agent gets the credential and figures it out,"
the flow has left Emberlink's model.
