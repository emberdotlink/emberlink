# Security Policy

## Supported versions

| Release line | Status | Security fixes |
|---|---|---|
| `0.3.x` (public source mirror, `v0.3.0` friendly preview, `v0.3.1` first public supported build) | **Active prerelease** | Yes — within the SLAs below |
| `0.2.x` and earlier | End-of-life | No — please upgrade to 0.3.x |
| Unreleased `main` | Development | Best-effort, not under SLA |

Per the v0.3.0 release boundary, the curated public source mirror may open before `v0.3.0`, `v0.3.0` remains a friendly preview to a small named cohort, and `v0.3.1` is the first public supported build. The same disclosure policy applies across that prerelease line.

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

We adopt the [disclose.io](https://disclose.io/) safe-harbor framework. Specifically:

> Activities conducted in a manner consistent with this policy will be considered authorized conduct, and we will not initiate legal action against you. If legal action is initiated by a third party against you in connection with activities conducted under this policy, we will take steps to make it known that your actions were conducted in compliance with this policy.

If you act in good faith, avoid privacy violations and service disruption, and give us reasonable time to address the issue before public disclosure, we will:

- Acknowledge your report in the CHANGELOG and release notes (with your permission)
- Work with you to understand and resolve the issue
- Not pursue legal action against you for the research

## Recognition

For v0.3.x we offer **discretionary credit** — recognition in the CHANGELOG and release notes, plus optional inclusion in a public hall-of-fame page that will ship alongside the v0.3.1 public supported build. We do **not** publish a bounty schedule or fixed dollar amount in v0.3.x. A small internal reserve exists to acknowledge particularly impactful reports at the maintainer's discretion.

A formal bounty programme (HackerOne or equivalent, with published amounts and tiers) is targeted for v0.4.0+. The earliest signal of that programme will be a published amendment to this file.

## Cryptographic components

Emberlink relies on standard, audited primitives (Ed25519 via `ed25519-dalek`, XChaCha20-Poly1305 via `chacha20poly1305`, Argon2id). Reports of weaknesses in these primitives should go to the upstream crate maintainers.

Reports of **implementation weaknesses** (incorrect primitive usage, padding oracles, timing side-channels, replay-attack gaps) are in scope and welcomed.

## PGP key

A PGP key for encrypted reports will be published here before the first public release.

## Verifying release artifacts

Every binary attached to a [GitHub Release](https://github.com/emberdotlink/emberlink/releases) ships with three independent supply-chain attestations:

1. **Minisign signature** (`<artifact>.minisig`) — produced by the release pipeline using a long-lived signing key whose public counterpart is embedded in `web/sh/install.sh`. The `install.sh` curl-pipe path verifies minisign automatically; the canonical install-time trust anchor.
2. **Sigstore keyless signature** (`<artifact>.sig` + `<artifact>.crt`) — produced by [`cosign sign-blob`](https://github.com/sigstore/cosign) using a short-lived Fulcio certificate bound to the GitHub Actions OIDC identity. No long-lived signing key for this layer; the certificate's transparency-log entry in [Rekor](https://search.sigstore.dev/) is the public auditable record.
3. **SLSA Level 3 build provenance** (`<artifact>.intoto.jsonl`) — produced by the [`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator) reusable workflow, attesting to the exact builder workflow, source commit, and inputs that produced each binary. The provenance file is published on the **dev repo** release (see "Build provenance — cross-repo publication" below).

### Prerequisites

Install the verifiers (one-time):

```bash
# cosign — https://docs.sigstore.dev/system_config/installation
brew install cosign                # macOS
# OR: go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# slsa-verifier — https://github.com/slsa-framework/slsa-verifier#installation
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

### Verify a downloaded binary

Replace `<bin>` with the artifact filename (for example `ember-x86_64-apple-darwin.tar.gz`) and `<tag>` with the release tag:

```bash
TAG=v0.X.Y
BIN=ember-x86_64-apple-darwin.tar.gz

# 1. Download the artifact, minisign sig, cosign sig, and certificate
#    from the PUBLIC release.
gh release download "$TAG" \
    --repo emberdotlink/emberlink \
    --pattern "$BIN" \
    --pattern "$BIN.minisig" \
    --pattern "$BIN.sig" \
    --pattern "$BIN.crt"

# 2. Verify the minisign signature (canonical install-time trust anchor).
#    The pubkey body lives in web/sh/install.sh and is also published at
#    https://emberlink.sh/release-pubkey.txt (when DNS is up).
minisign -Vm "$BIN" -p ember-release.pub

# 3. Verify the sigstore keyless signature.
#    NOTE: the certificate-identity-regexp points at emberdotlink/emberlink-dev,
#    NOT emberlink — release workflows run on the dev repo and publish to the
#    public repo via a cross-repo GitHub App. See "Build provenance —
#    cross-repo publication" below.
cosign verify-blob \
    --certificate "$BIN.crt" \
    --signature   "$BIN.sig" \
    --certificate-identity-regexp "^https://github\.com/emberdotlink/emberlink-dev/\.github/workflows/(release(-assets|-installers-linux)?\.yml)@.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$BIN"

# 4. (Optional, advanced) Verify the SLSA build provenance.
#    Provenance is published on the DEV repo's release (where the builder
#    workflow ran). Source-uri pins the build to the dev source repository.
gh release download "$TAG" \
    --repo emberdotlink/emberlink-dev \
    --pattern "*.intoto.jsonl"
slsa-verifier verify-artifact \
    --provenance-path emberlink.intoto.jsonl \
    --source-uri github.com/emberdotlink/emberlink-dev \
    "$BIN"
```

If all the commands print a success message, the binary was signed by our release pipeline and built from the exact source commit named in the provenance. Any tamper, substitution, or rebuild outside the pipeline will fail one of these checks.

If verification **fails**, do not run the binary. File a security report (see "Reporting a Vulnerability" above).

### What the attestations protect against

| Threat                                              | Protected by                |
| --------------------------------------------------- | --------------------------- |
| Mirror or CDN swap of the tarball                   | minisign + cosign           |
| Compromised maintainer account uploading a fake bin | cosign + Rekor transparency |
| Builder tampering (modified workflow YAML)          | SLSA provenance             |
| Out-of-band rebuild claiming to be official         | SLSA provenance source-uri  |
| Stolen long-lived minisign key                      | requires rotating the embedded pubkey in install.sh; install-time fail-closed via cosign in parallel |

### Build provenance — cross-repo publication

Release artifacts on [`emberdotlink/emberlink`](https://github.com/emberdotlink/emberlink) (this public repo) are built by workflows in [`emberdotlink/emberlink-dev`](https://github.com/emberdotlink/emberlink-dev) (the private dev repo) and pushed to the public release page via a single-purpose GitHub App scoped `contents:write` only on the public repo. The minisign signing key is stored as a GitHub repo secret on the dev repo; it never resides on the public repo.

**What this means for verification:**

- **Minisign signatures** are the canonical install-time trust anchor. The public-key body is embedded in `web/sh/install.sh`. Minisign is independent of any GitHub identity — it attests that the artifact was signed by the holder of the Emberlink release private key (custody: maintainer-held hardware + password-manager backup).

- **Cosign keyless signatures** carry a Fulcio certificate whose `Subject` claim names the WORKFLOW ORIGIN: `repo:emberdotlink/emberlink-dev:ref:refs/tags/<tag>`, NOT `emberdotlink/emberlink`. This is intentional. The dev repo is where security-lane code review happens (CODEOWNERS-gated paths, audit pipeline, signed-commit policy); the public repo is a publication artifact, not a CI surface. Cosign verifiers MUST use the dev-repo identity regex (the `verify-blob` command above already does).

- **SLSA Level 3 provenance** (`.intoto.jsonl`) attests the build's source-uri as `github.com/emberdotlink/emberlink-dev` and is uploaded to the dev repo's release page. To verify, download the provenance from `emberdotlink/emberlink-dev` while downloading the artifact from `emberdotlink/emberlink`. The provenance pinning prevents an attacker from claiming a binary was built from a different commit.

**Why we ship it this way:**

Keeping `emberdotlink/emberlink` free of workflows and secrets reduces blast radius — a compromise of the public repo doesn't grant access to the release-signing identity, Fulcio OIDC identity, or build pipeline. Workflows and signing material live on the dev repo where access controls are tighter (private, smaller contributor set, branch-protection on `main`, CODEOWNERS on the `.github/workflows/` path). The public repo is a read-only publication mirror by design — friendly users fork it without inheriting CI machinery they cannot run.

**Threat-model implication:** an attacker with read access to public emberdotlink/emberlink can observe what shipped (a feature, not a bug — the goal is transparency). They cannot trigger a release, sign a binary, or impersonate the build pipeline from the public repo. To compromise a release they would need to compromise emberdotlink/emberlink-dev, and even then the minisign private key — which lives in repo secrets but is rotated on demand — provides a parallel defense layer.

### Pinned tooling versions

Supply-chain action versions live in `.github/workflows/release-assets.yml`. Current pins:

- `sigstore/cosign-installer` — pinned by SHA (commented with semver tag)
- `slsa-framework/slsa-github-generator` — pinned by **tag** (this is the SLSA-required form: the verifier validates against tag identity in the transparency log; SHA pinning would defeat the trust model)
