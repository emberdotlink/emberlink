# Support Levels and Release Posture

The public docs site intentionally separates **what exists** from **what is
fully supported**.

That is why pages on this site carry one of three labels:

- `Supported`
- `Preview`
- `Experimental`

## What the labels mean

### Supported

Use `Supported` to mean:

- start here first
- this is part of the current public operator or developer contract
- the docs are expected to stay reasonably stable

On the current site, examples include core CLI/operator guidance and the
receipt/audit evidence model.

### Preview

Use `Preview` to mean:

- the surface is real and useful
- the contract is truthful
- the details may still shift before the first broadly supported public build

This is the most common current posture for Emberlink’s public story.

### Experimental

Use `Experimental` to mean:

- the surface exists or is publishable enough to document
- the contract is still moving faster than the main product path
- advanced users can evaluate it, but they should expect churn and should not
  treat it as the default path

The SDK pages currently sit here on purpose.

## Current release truth

Today’s public repository and docs site may be visible **before** the first
broadly supported build.

The current milestone split is:

- `v0.3.0`: friendly preview / invite-only proof lane
- `v0.3.1`: first planned public supported build and install funnel

The `v0.3.0` proof lane is deliberately narrow: managed Claude Code and Codex
sessions, brokered Git/GitHub authority through `ember-gh` and `ember-git`, and
signed Receipts. Additional launchers and Constructs can exist in code or
development lanes without being part of this validated public story.

That means public visibility does **not** imply full self-serve support yet.
Pre-release limitations are handled through the invite/onboarding channel
for the current friendly cohort.

## What users should do today

If you are deciding how to evaluate Ember today, there are two honest entry
paths:

### 1. Friendly-preview operator path

If you are in the named friendly cohort:

- use the signed preview artifact you were given
- follow the canonical onboarding flow
- start with:

```bash
ember init --for claude
ember status
ember claude
```

If Codex is your agent surface, use the supported advanced launcher path:

```bash
codex login
ember init --for codex
ember status
ember codex
```

Codex starts from Codex's native login flow. Emberlink can then import and
broker runtime authority with operator consent during `ember init --for codex`.

### 2. Public source-evaluation path

If you are evaluating from the public source mirror:

```bash
cargo install --locked --path crates/emberlink-cli --bin ember
ember init --for claude
```

This path is real, but it is still a pre-release source-build path rather than
the long-term supported public installer story.

If you only want the shortest supported-first reading order on this site, use:

1. [Install and first run](./install-and-first-run.md)
2. [CLI and troubleshooting](../use/cli-and-troubleshooting.md)
3. [CLI reference](../reference/cli-reference.md)

## Why this distinction matters

Emberlink’s product claim is about **authority mediation**, not just about
shipping a CLI binary. The install, daemon, launcher, GitHub, and evidence
surfaces all have to line up honestly.

So the docs site distinguishes:

- what is visible
- what is usable
- what is genuinely part of the supported public contract

## Related pages

- [Install and first run](./install-and-first-run.md)
- [CLI and troubleshooting](../use/cli-and-troubleshooting.md)
- [GitHub setup and auth](../use/github-setup-and-auth.md)
