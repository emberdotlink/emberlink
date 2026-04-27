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

## Verifying release artifacts

Every binary attached to a [GitHub Release](https://github.com/emberdotlink/emberlink/releases) ships with two independent supply-chain attestations:

1. **Sigstore keyless signature** (`<artifact>.sig` + `<artifact>.crt`) produced by [`cosign sign-blob`](https://github.com/sigstore/cosign) using a short-lived Fulcio certificate bound to the GitHub Actions OIDC identity. No long-lived signing key exists; the certificate's transparency-log entry in [Rekor](https://search.sigstore.dev/) is the public auditable record.
2. **SLSA Level 3 build provenance** (`<artifact>.intoto.jsonl`) produced by the [`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator) reusable workflow, attesting to the exact builder workflow, source commit, and inputs that produced each binary.

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

# 1. Download the artifact, its signature, certificate, and provenance.
gh release download "$TAG" \
    --repo emberdotlink/emberlink \
    --pattern "$BIN" \
    --pattern "$BIN.sig" \
    --pattern "$BIN.crt" \
    --pattern "*.intoto.jsonl"

# 2. Verify the sigstore signature (keyless via Fulcio OIDC).
#    The certificate identity must match the GitHub Actions release workflow.
cosign verify-blob \
    --certificate "$BIN.crt" \
    --signature   "$BIN.sig" \
    --certificate-identity-regexp "^https://github.com/emberdotlink/emberlink/.github/workflows/release-assets\.yml@.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$BIN"

# 3. Verify the SLSA build provenance.
#    Pins the build to this exact source repository.
slsa-verifier verify-artifact \
    --provenance-path emberlink.intoto.jsonl \
    --source-uri github.com/emberdotlink/emberlink \
    "$BIN"
```

If both commands print a success message, the binary was signed by our release pipeline and built from the exact source commit named in the provenance. Any tamper, substitution, or rebuild outside the pipeline will fail one of these checks.

If verification **fails**, do not run the binary. File a security report (see "Reporting a Vulnerability" above).

### What the attestations protect against

| Threat                                              | Protected by                |
| --------------------------------------------------- | --------------------------- |
| Mirror or CDN swap of the tarball                   | cosign signature            |
| Compromised maintainer account uploading a fake bin | cosign + Rekor transparency |
| Builder tampering (modified workflow YAML)          | SLSA provenance             |
| Out-of-band rebuild claiming to be official         | SLSA provenance source-uri  |
| Stolen long-lived signing key                       | keyless — no such key       |

### Pinned tooling versions

Supply-chain action versions live in `.github/workflows/release-assets.yml`. Current pins:

- `sigstore/cosign-installer` — pinned by SHA (commented with semver tag)
- `slsa-framework/slsa-github-generator` — pinned by **tag** (this is the SLSA-required form: the verifier validates against tag identity in the transparency log; SHA pinning would defeat the trust model)

