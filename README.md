# Emberlink

**Keep the keys. Grant the action. Prove the result.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-8e44ad.svg)](public-docs/get-started/support-levels-and-release-posture.md)

Emberlink is a local authority platform for AI agents.

It is the Grant Warden: a local daemon that keeps custody of secrets, payment
sources, sensitive data, and other authority-bearing resources; grants bounded
authority to agent sessions and actions; and emits signed Receipts afterward.

The model is general. A Grant can bound a credential, an LLM session, a payment
source, a data source, compute, or another resource an agent should not receive
as standing ambient power.

The current `v0.3.0` friendly release validates that model through a deliberately
small surface: managed Claude Code and Codex sessions, brokered Git/GitHub
authority, and signed Receipts.

```text
raw-token agent
  agent process has a standing secret, token, or broad permission
  that material can do everything it allows
  evidence is scattered across tool logs and transcripts

emberlink agent
  agent asks for an action
  emberd checks the Persona, Grant, policy, and target
  brokered authority is materialized only for the allowed use
  a signed Receipt records what authority backed the work
```

## What You Can Validate Today

`v0.3.0` is a proof surface for the Emberlink model, not the full future tool
catalog.

| Surface | What it demonstrates |
|---|---|
| `ember claude` | Claude Code launched as a managed agent session with Persona, Grant, daemon mediation, and Receipts. |
| `ember codex` | Codex launched as a managed agent session; Codex starts from native login, then Emberlink can import and broker runtime authority with operator consent. |
| `ember-gh` | GitHub authority brokered behind familiar `gh` workflows inside a managed session. |
| `ember-git` | Git authority brokered behind familiar `git` workflows inside a managed session. |
| Receipts and audit | Signed evidence for delegated authority and mediated work. |

Additional launchers such as `ember cursor` and `ember gemini`, and additional
Constructs such as `ember-aws`, `ember-kubectl`, and other provider/tool lanes,
are experimental or in flight. Use the support labels in the public docs before
building on them.

## Install

Emberlink is pre-1.0. If you are in the friendly-preview cohort, use the signed
preview artifact and onboarding notes you were given.

If you are evaluating from the public source mirror:

```bash
git clone https://github.com/emberdotlink/emberlink.git
cd emberlink
cargo install --locked --path crates/emberlink-cli --bin ember
```

Prerequisites for the source-build path:

- Rust 1.96.0 through [rustup](https://rustup.rs)
- Git
- Docker only if you plan to use isolated `ember sandbox ...` flows

## First Run: Claude Code

Start here unless you already know you want the Codex path.

```bash
ember init --for claude
ember status
ember claude
```

`ember init --for claude` prepares the managed launcher path and offers to
repair or install the daemon if the daemon-backed path is not ready yet.

If Claude runtime auth is available during init, Emberlink can place it under
daemon custody for brokered use by the managed session. If not, Claude's own
upstream auth can remain ambient while Emberlink still mediates the Git,
GitHub, and evidence side of the session.

## Codex Path

Use this path when Codex is the agent surface you intend to run:

```bash
codex login
ember init --for codex
ember status
ember codex
```

Codex starts from Codex's native login flow. During `ember init --for codex`,
Emberlink can import the local Codex auth material with operator consent and
refresh the brokered OpenAI runtime grant used by managed Codex sessions.

## Brokered Git and GitHub

The `v0.3.0` tool proof is Git/GitHub mediation.

After the GitHub lane is configured and you launch a managed Claude or Codex
session, use the familiar commands from inside that session:

```bash
git push
gh pr create
```

The command a user or agent sees may still be `git` or `gh`. The Emberlink
artifact carrying the authority boundary is `ember-git` or `ember-gh`. That
distinction preserves normal tool muscle memory while keeping action
classification, grant evaluation, credential materialization, and receipt
emission inside the daemon-backed model.

For setup and repair, start with:

```bash
ember github status
ember github setup
ember doctor
```

## Receipts

The receipt story is part of the product, not an afterthought. After a managed
session performs credential-bearing work, inspect the evidence:

```bash
ember receipt list
ember receipt show <id>
ember audit query
```

Receipts are signed artifacts that answer a different question than logs.
Logs say what a process reported. Receipts say whose authority backed a
delegated action and what was materialized for that action.

## Core Concepts

- **Warden**: the local daemon, `emberd`, that holds custody and decides when
  authority can be released.
- **Grant**: a scoped, time-bound, revocable authority statement.
- **Persona**: the runtime identity an agent session acts under.
- **Construct**: a mediated tool surface such as `ember-gh` or `ember-git`.
- **Receipt**: signed evidence of delegated authority and mediated work.

The important shift is that agents do not become the authority root. They ask
for authority. `emberd` decides whether that request is inside the current
Grant, narrows or denies it as needed, and records evidence afterward.

## Support Posture

The source mirror may be visible before the first broadly supported public
installer. Treat `v0.3.0` as a friendly-preview and source-evaluation release.

| Surface | Current posture |
|---|---|
| `ember init --for claude` and `ember claude` | supported friendly path |
| `ember init --for codex` and `ember codex` | supported advanced path |
| `ember-gh` and `ember-git` | core `v0.3.0` brokered-tool proof surface |
| `ember receipt ...` and `ember audit ...` | supported evidence surface |
| `ember cursor`, `ember gemini` | experimental / in flight |
| Additional Constructs such as `ember-aws` and `ember-kubectl` | experimental / in flight |
| MCP integration | preview |
| TypeScript and Python SDKs | experimental |

For the exact public contract, read
[Support Levels and Release Posture](public-docs/get-started/support-levels-and-release-posture.md).

## Read Next

- [Quickstart](QUICKSTART.md)
- [Install and first run](public-docs/get-started/install-and-first-run.md)
- [GitHub setup and auth](public-docs/use/github-setup-and-auth.md)
- [Grant Warden model](public-docs/concepts/grant-warden.md)
- [Receipts and audit](public-docs/concepts/receipts-and-audit.md)
- [CLI reference](public-docs/reference/cli-reference.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For design or integration work, start
with the Grant Warden model, the Construct docs, and the support posture page
so changes line up with the current authority boundary.

## License

Apache-2.0
