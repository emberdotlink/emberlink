

> [!NOTE]
> Support level: **Preview**. Reviewed: 2026-06-17. Status: current.

# Choose an Integration Surface

Emberlink exposes more than one user-facing surface, but they are not equal.

The current public truth is:

1. **Launcher path first**
2. **MCP second**
3. **SDKs are experimental**

## Use `ember claude` when

Choose the launcher path if you want the most complete current product story.

This is the best fit when:

- you are an operator using Claude Code
- you want the managed daemon/session path
- you want the most truth-backed v0.3.x workflow

The launcher path is the current headline lane because it exercises the real
daemon, grant, vault, receipt, and tool-brokering story together.

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
| `emberlink-mcp` | **Preview** | Tool/server integration in MCP-capable environments |
| TypeScript / Python SDKs | **Experimental** | Custom programmatic integration against a moving and not-yet-fully-audited contract |

## What not to do

Do not assume these surfaces are interchangeable:

- MCP is not a second trust root
- the SDKs are not a more-supported replacement for the launcher path
- the launcher path is not the right answer for every non-Claude environment

Pick the surface that matches your environment and your tolerance for churn.

## Next pages

- [Constructs and mediated tools](./constructs-and-mediated-tools/)
- [MCP integration](./mcp-integration/)
- [TypeScript SDK](../experimental/sdk-typescript/)
- [Python SDK](../experimental/sdk-python/)
- [Install and first run](../get-started/install-and-first-run/)
