

> [!NOTE]
> Support level: **Preview**.
> Source truth: `README.md`, `CONTEXT.md`, `docs/current-architecture.md`.
# The Grant Warden Model

Most agent systems hand a process a raw token, a broad OAuth scope, or an
ambient platform permission. Emberlink changes that boundary.

The core model is:

- the **local daemon** keeps custody of credentials
- the agent receives a **grant**, not the raw standing secret
- the daemon mediates use of that authority
- every sensitive action leaves behind a signed **Receipt**

The product story is not "another secret manager." It is "a local authority
boundary for agent work."

## Core nouns

- **Warden** — the local authority daemon
- **Grant** — scoped, time-bound delegated authority
- **Receipt** — signed audit artifact describing what happened
- **Construct** — a mediated execution surface for credentialed tool use

## Why this matters

The point is not only secret storage. The point is:

- revocable authority
- explicit scope
- auditability
- a path to human approval where it matters

For the current operator command contract around that model, see
[Grants and approvals](../reference/grants-and-approvals/).

