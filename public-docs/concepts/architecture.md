

> [!NOTE]
> Support level: **Preview**.
> Source truth: `docs/current-architecture.md`, `docs/cli-reference.md`, `README.md`.
# Architecture Overview

The primary live product is a **local daemon-centered system**.

At a high level:

- `emberd` is the runtime authority
- CLI, PATH-shadowed constructs, MCP, and GUI are daemon clients
- the current live authority path is the **local Unix socket**

## Main runtime roles

- **`emberd`** — vault/store access, broker registry, session lifecycle,
  receipt identity, dashboard, and local proxies
- **`ember` CLI** — operator surface, partly daemon-backed and partly still a
  mixed local/debug surface
- **Construct shims** — PATH-shadowed wrappers that classify argv locally and
  then re-classify server-side
- **`emberlink-mcp`** — MCP server that talks to the daemon socket

## Current product truth

- The installed separate-uid daemon posture is the canonical operator path.
- The local Unix socket is the real current trust boundary.
- GitHub App mediation is the preferred GitHub lane; PAT is degraded fallback.
- The current public mediated-tool cohort is `ember-gh`, `ember-git`, and
  `ember-kubectl`.
- Some deeper headless / advanced agent surfaces are still moving and should be
  treated as pre-release.

For the detailed current mechanism map, the repo's canonical source remains
`docs/current-architecture.md`.

For the public explanation of the current mediated-tool lane, see
[Constructs and mediated tools](../build/constructs-and-mediated-tools/).

