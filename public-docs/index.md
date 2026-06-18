# Emberlink Docs

Emberlink is the **Grant Warden for AI agents**.

It gives agents a way to act without handing them standing secrets or other
authority-bearing resources. The local daemon keeps custody, grants bounded
authority at action time, and emits signed receipts so you can later prove what
happened.

```text
raw-token world

  agent process
      |
      |  standing secret
      |  payment source
      |  sensitive data
      |  or broad permission
      v
  production tool / API


emberlink world

  agent space
      |
      |  asks for a tool action
      v
  authority space
      |
      |  emberd checks grant
      |  and narrows authority
      v
  execution space
      |
      |  action runs
      v
  signed receipt
```

The docs are organized so you can enter at your current depth:

- **Learn the model** if you are asking what Emberlink is and why it exists.
- **Use Ember** if you want the supported local operator path.
- **Build with Emberlink** if you want to integrate an agent, MCP server, SDK,
  or Construct.
- **Check reference** when you need exact command posture and support labels.

## Start with the model

![A standing credential stays with emberd, a grant bounds the requested action, narrowed authority is materialized for execution, and receipt evidence survives](assets/diagrams/authority-lifecycle.svg)

Read these first if the words grant, Construct, receipt, and persona are still
new:

- [The Grant Warden Model](./concepts/grant-warden.md)
- [One Action End to End](./concepts/one-action-end-to-end.md)
- [Current Primitives](./concepts/primitives.md)
- [Runtime Flow](./concepts/runtime-flow.md)
- [Security Model](./concepts/security-model.md)
- [Architecture Overview](./concepts/architecture.md)
- [Receipts and Audit](./concepts/receipts-and-audit.md)

The goal is not to memorize jargon. The goal is to understand the shape of
delegated authority: who is asking, what authority is needed, where that
authority is materialized, and what evidence survives the action.

If you only read one concept page after the model, read
[One Action End to End](./concepts/one-action-end-to-end.md). It follows a
single `gh pr create` from managed session to daemon decision, materialized
authority, and receipt evidence.

## What you can use today

| Surface | Current label | Start here |
|---|---|---|
| Install, initialize, repair, and inspect the local daemon path | Supported | [Install and First Run](./get-started/install-and-first-run.md) |
| Claude Code managed sessions | Supported | [CLI Reference](./reference/cli-reference.md) |
| Codex managed sessions | Supported, advanced | [Install and First Run](./get-started/install-and-first-run.md#codex-path) |
| Grants, approval queues, receipts, and audit evidence | Supported | [Grants and Approvals](./reference/grants-and-approvals.md) and [Receipts and Audit](./concepts/receipts-and-audit.md) |
| GitHub setup and brokered Git/GitHub authority | Supported | [GitHub Setup and Auth](./use/github-setup-and-auth.md) |
| Bundled mediated tools: `ember-gh` and `ember-git` | Supported | [Constructs and Mediated Tools](./build/constructs-and-mediated-tools.md) |
| Additional launchers: `ember cursor`, `ember gemini` | Experimental | [Support Levels and Release Posture](./get-started/support-levels-and-release-posture.md) |
| Additional Constructs: `ember-aws`, `ember-kubectl`, and other provider lanes | Experimental | [Constructs and Mediated Tools](./build/constructs-and-mediated-tools.md) |
| MCP server integration | Preview | [MCP Integration](./build/mcp-integration.md) |
| Sandbox and isolated execution | Preview | [Sandbox and Isolated Execution](./reference/sandbox-and-isolated-execution.md) |
| TypeScript and Python SDKs | Experimental | [Choose an Integration Surface](./build/choosing-an-integration-surface.md) |

The table is intentionally product-facing. Code may contain more machinery
than the public contract exposes; use the labels when deciding what to rely on.

## Use Ember

If you are evaluating Emberlink today, follow the supported path first:

- [Install and First Run](./get-started/install-and-first-run.md)
- [CLI and Troubleshooting](./use/cli-and-troubleshooting.md)
- [GitHub Setup and Auth](./use/github-setup-and-auth.md)
- [Warden Console Prototype](./use/warden-console-prototype.md)
- [Support Levels and Release Posture](./get-started/support-levels-and-release-posture.md)

The current `v0.3.0` friendly path validates the model with managed Claude Code
and Codex sessions, brokered Git/GitHub authority through `ember-gh` and
`ember-git`, and signed Receipts. `ember codex` starts from Codex's native login
flow, then Emberlink can import and broker runtime authority with operator
consent.

## Build with Emberlink

Start here when you are deciding how to wire Emberlink into your own system:

- [Choose an Integration Surface](./build/choosing-an-integration-surface.md)
- [Constructs and Mediated Tools](./build/constructs-and-mediated-tools.md)
- [Construct Authoring Model](./build/build-a-construct.md)
- [MCP Integration](./build/mcp-integration.md)
- [TypeScript SDK](./experimental/sdk-typescript.md)
- [Python SDK](./experimental/sdk-python.md)

The deeper builder path starts with one question: what current action needs
delegated authority? Once you can answer that, the rest of the model becomes
mechanical: declare the action, bind it to a grant need, choose how authority
is materialized, run the action, and verify the receipt.

## Support posture

Emberlink uses three public support postures:

- **Supported** means the surface is part of the current public operator story.
- **Preview** means the surface is real and intentional, but still settling.
- **Experimental** means the surface is useful for early builders who can
  tolerate churn.

For the current release boundary and support contract, read
[Support Levels and Release Posture](./get-started/support-levels-and-release-posture.md).
