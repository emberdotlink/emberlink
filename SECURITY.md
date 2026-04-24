# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report security issues by emailing `security@emberlink.dev` or through GitHub's private vulnerability reporting:

1. Go to the [Security Advisories](https://github.com/emberdotlink/emberlink/security/advisories) tab
2. Click "Report a vulnerability"

## What to include

Your report should contain as much of the following as possible:

- **Type of issue** — buffer overflow, injection, authentication bypass, cryptographic weakness, etc.
- **Location** — file path, line number, function name
- **Affected component** — daemon, proxy, sandbox, CLI, SDK, relay, extension, dashboard
- **Step-by-step reproduction** — exact commands, inputs, and expected vs actual behavior
- **Proof of concept or exploit code** — if available (only submit what you're comfortable sharing)
- **Impact** — what an attacker could achieve
- **Suggested fix** — if you have one (not required)

## Response timeline

- **72 hours** — initial acknowledgement
- **7 days** — preliminary assessment (valid / needs-more-info / not-applicable)
- **30 days** — target fix-and-release for critical and high-severity issues
- **90 days** — public disclosure unless otherwise agreed with the reporter

## Scope

**In scope:**

- The `ember` daemon and all its sub-binaries (`emberd`, `ember-proxy`, `ember-sandbox`, `ember-dashboard`)
- The `emberlink-mcp` server
- All workspace crates (`crates/core-*`, `crates/ember-daemon`, `crates/ember-*`, `crates/emberlink-*`)
- The TypeScript and Python agent SDKs (`packages/agent-sdk-ts`, `packages/agent-sdk-py`)
- The landing page at https://ember.link
- The relay server when run in any documented mode

**Out of scope:**

- Third-party dependencies (please report upstream)
- Attacks that require root access on the machine running the daemon
- Physical attacks on the user's device
- Denial-of-service attacks that require sustained resource consumption from within a privileged context
- Social engineering of project maintainers

## Safe harbor

If you act in good faith, avoid privacy violations and service disruption, and give us reasonable time to address the issue before public disclosure, we will:

- Acknowledge your report in the CHANGELOG and release notes (with your permission)
- Work with you to understand and resolve the issue
- Not pursue legal action against you for the research

## Cryptographic components

Emberlink relies on standard, audited primitives (Ed25519 via `ed25519-dalek`, XChaCha20-Poly1305 via `chacha20poly1305`, Argon2id). Reports of weaknesses in these primitives should go to the upstream crate maintainers.

Reports of **implementation weaknesses** (incorrect primitive usage, padding oracles, timing side-channels, replay-attack gaps) are in scope and welcomed.

## PGP key

A PGP key for encrypted reports will be published here before the first public release.
