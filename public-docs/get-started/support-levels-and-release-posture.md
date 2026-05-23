

> [!NOTE]
> Support level: **Preview**.
> Source truth: `README.md`, `QUICKSTART.md`, `project design notes`, `release-notes`.
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

- this is part of the current public operator or developer contract
- the docs are expected to stay reasonably stable
- the team intends this to be a real user-facing surface, not just a prototype

On the current site, examples include core CLI/operator guidance and the
receipt/audit evidence model.

### Preview

Use `Preview` to mean:

- the surface is real and useful
- it is still pre-release or still tightening around the edges
- the contract is truthful, but it may still shift before the first broadly
  supported public build

This is the most common current posture for Emberlink’s public story.

### Experimental

Use `Experimental` to mean:

- the surface exists or is publishable enough to document
- the contract is still moving faster than the main product path
- advanced users can evaluate it, but they should expect churn

The SDK pages currently sit here on purpose.

## Current release truth

Today’s public repository and docs site may be visible **before** the first
broadly supported build.

The current milestone split is:

- `v0.3.0` — friendly preview / invite-only proof lane
- `v0.3.1` — first planned public supported build and install funnel

That means public visibility does **not** imply full self-serve support yet.

## What users should do today

There are two honest entry paths right now:

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

### 2. Public source-evaluation path

If you are evaluating from the public source mirror:

```bash
cargo install --locked --path crates/emberlink-cli --bin ember
ember init --for claude
```

This path is real, but it is still a pre-release source-build path rather than
the long-term supported public installer story.

## Why this distinction matters

Emberlink’s product claim is about **authority mediation**, not just about
shipping a CLI binary. The install, daemon, launcher, GitHub, and evidence
surfaces all have to line up honestly.

So the docs site distinguishes:

- what is visible
- what is usable
- what is genuinely part of the supported public contract

## Related pages

- [Install and first run](./install-and-first-run/)
- [CLI and troubleshooting](../use/cli-and-troubleshooting/)
- [GitHub setup and auth](../use/github-setup-and-auth/)
