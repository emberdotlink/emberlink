# Choose an Integration Surface

Emberlink exposes more than one user-facing surface, but they are not equal.

The current public truth is:

1. **Launcher path first**
2. **Constructs for credential-bearing command execution**
3. **MCP for MCP-capable tool graphs**
4. **SDKs are experimental**

## Use `ember claude` when

Choose the launcher path if you want the most complete current product story.

This is the best fit when:

- you are an operator using Claude Code
- you want the managed daemon/session path
- you want the most truth-backed v0.3.x workflow

The launcher path is the current headline lane because it exercises the real
daemon, grant, vault, receipt, and tool-brokering story together.

## Use `ember codex` when

Choose the Codex launcher when you already use Codex and are comfortable with
the advanced path.

This is the best fit when:

- you have already authenticated Codex with `codex login`
- you want Emberlink session registration and daemon mediation around Codex
- you understand that Codex starts from Codex's native login path before
  Emberlink imports and brokers runtime authority with operator consent

`ember codex` is real and supported, but it is not the headline friendly
onboarding lane. If you are debugging a first run and do not specifically need
Codex, start with `ember claude`.

## Use a Construct when

Choose a Construct when the integration problem is credential-bearing command
execution.

This is the best fit when:

- the agent already uses a CLI such as `gh` or `git`
- the sensitive moment is a tool action that needs delegated authority
- you need action classification, grant evaluation, materialization, and
  receipt evidence around that tool action

Constructs are not a general plugin system. They are authority gates for
actions where credentials and accountability matter.

For `v0.3.0`, the validated public Construct proof surface is `ember-gh` and
`ember-git`. Additional Constructs such as `ember-aws`, `ember-kubectl`, and
other provider lanes are experimental or in flight.

## Use `emberlink-mcp` when

Choose MCP when you already have an MCP-capable environment and want the daemon
exposed as a tool server.

This is the best fit when:

- your agent environment already speaks MCP
- you want daemon tools without using the Ember launcher
- you are integrating Emberlink into an existing MCP tool graph

MCP is a real shipped surface, but it is not the main onboarding lane.

## Use the SDKs when

Choose the TypeScript or Python SDK only when you are prepared to track a
moving contract.

This is the best fit when:

- you need a programmatic daemon client in custom code
- you are building a bespoke agent shell or automation layer
- you can tolerate pre-release churn in the SDK/headless story

The SDKs are intentionally labeled **Experimental** on this site because the
broader headless and programmatic contract is still less settled than the main
operator path and the package story is not yet audited to the same standard as
the launcher or MCP lanes.

## Comparison

| Surface | Current state | Best for |
|---|---|---|
| `ember claude` | **Supported** | Friendly operators and the main pre-release user story |
| `ember codex` | **Supported, advanced** | Codex users who start from native login and want brokered runtime authority inside a managed session |
| `ember-gh`, `ember-git` | **Supported** | The `v0.3.0` brokered Git/GitHub proof surface |
| Additional Constructs | **Experimental** | Provider/tool lanes such as `ember-aws` and `ember-kubectl` that are still being validated |
| `emberlink-mcp` | **Preview** | Tool/server integration in MCP-capable environments |
| TypeScript / Python SDKs | **Experimental** | Custom programmatic integration against a moving and not-yet-fully-audited contract |

## What not to do

Do not assume these surfaces are interchangeable:

- MCP is not a second trust root
- the SDKs are not a more-supported replacement for the launcher path
- Constructs are not interchangeable with MCP
- the launcher path is not the right answer for every custom or headless
  environment

Pick the surface that matches your environment and your tolerance for churn.

## Next pages

- [Constructs and mediated tools](./constructs-and-mediated-tools.md)
- [Construct Authoring Model](./build-a-construct.md)
- [MCP integration](./mcp-integration.md)
- [TypeScript SDK](../experimental/sdk-typescript.md)
- [Python SDK](../experimental/sdk-python.md)
- [Install and first run](../get-started/install-and-first-run.md)
