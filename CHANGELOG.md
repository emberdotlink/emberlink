# Changelog

Notable public-facing changes to Emberlink are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Public source mirror scope tightened.** The public mirror now excludes
  recording demos, top-level deployment infrastructure, maintainer install
  templates, internal work coordination history, and internal pre-release
  tracking docs. Public build inputs that crates need at compile time now live
  under crate-owned `templates/` paths instead of top-level deployment
  directories.
- **README and public support maps rewritten for first-time public readers.**
  The docs now pitch Emberlink as a broad local authority platform while making
  the `v0.3.0` proof surface explicit: managed Claude Code and Codex sessions,
  brokered Git/GitHub authority through `ember-gh` and `ember-git`, and signed
  Receipts. Additional launchers and Constructs are documented as experimental
  or in flight until validated.
- **Manifesto focused on protocol commitments.** The manifesto now stays
  centered on the Grant Warden model, local-first authority mediation,
  Receipts, and the protocol's no-required-infrastructure property.
- **Release posture language clarified.** Public docs now state that repository
  visibility can precede the first broadly supported install funnel. The
  current support boundary is documented through `QUICKSTART.md` and the public
  support-level page, with pre-release details handled through the invite and
  onboarding channel.

## [0.3.0] - 2026-05-14

Friendly-preview release for the Grant Warden path. Prior 0.1.x and 0.2.x
tags were internal milestones, not broadly announced public releases.

### Added

- **Hardware-bound vault encryption on Apple Silicon.** The daemon's
  master-encryption-key passphrase is wrapped against a
  Secure-Enclave-resident P-256 key via ECIES. The wrapping key never
  leaves the SE. Requires the daemon to run under a dedicated `ember`
  service account; an attacker with code execution as the operator's
  user cannot read the vault at rest without coercing the
  separately-uid'd daemon.
- **Tamper-evident audit chain.** Every signed Receipt is hash-linked
  to the prior Receipt and persisted to an append-only journal.
  Daemon startup samples the chain; tamper detection refuses
  write-class socket methods and fails identity-init closed.
- **Receipt format v2.** Atomic and session-scope receipts.
  Offline-verifiable via the bundled `ember receipt verify` CLI or
  compatible verifier tooling.
- **macOS installer.** Notarized + stapled `.pkg`. Daemon installs as
  a LaunchDaemon under a dedicated `ember` service account.
- **Friendly preview: brokered Git/GitHub actions.** `git push` and
  `gh pr create` route through Emberlink credential brokers that classify argv,
  inject credentials into each tool's native auth contract at the moment of
  execution, and emit signed Receipts on exit. The agent process never sees the
  credential.
- **Biometric gating on grants.** `ember grant create
  --require-biometric` enforces operator-presence proof (FIDO2,
  Touch ID, or platform passkey) at credential-vending time for
  agent-mediated access through `broker.resolve`.
- **WebAuthn persona enrollment.** Each persona binds to a hardware
  authenticator (YubiKey, Touch ID, platform passkey).

### Security

- Vault MEK derivation: in-memory passphrase zeroized on drop, AAD
  binding, Argon2id parameter pin, per-sign integrity check.
- Broker exec credential injection on Linux uses memfd-sealed
  ephemeral env so credentials are not readable from `/proc`.

### Release posture

- `v0.3.0` is a friendly-preview build, not a broad general-availability
  release.
- The current first-run path is centered on the local daemon, the `ember`
  CLI, and managed agent launchers.
- Breaking changes remain possible before 1.0. Daemon and CLI compatibility is
  scoped to a minor version.

## [0.2.0] - 2026-04-14

First documented release. Earlier 0.0.x and 0.1.x development was internal;
0.2.0 is the snapshot at which the daemon trust-broker model stabilized and
the friendly-preview surfaces (CLI, dashboard, MCP, SDKs) reached usable
parity.

Note: between 0.2.0 and 0.2.28 the project ran a daily auto-bump cadence
to exercise the release pipeline; intermediate version tags carry no
distinct user-visible behavior beyond what's listed below. The version
range is consolidated here. From 0.3.0 onward, each release tag
represents a discrete change set.

### Breaking changes

- Composite grant statements shape — grants now bundle multiple action
  scopes (`statements[]`) into a single approval moment; receipts cover
  the whole bundle. Required for token/dollar-budget grants and
  multi-credential workflows.
- Renamed `--budget-cents` to `--budget-usd` on `ember grant create`.
- Removed `ember hook check`; integrate via MCP server (`emberlink-mcp`)
  instead. Existing Claude Code integrations should switch to the
  `~/.claude/settings.json` `mcpServers.ember` configuration documented
  in the README.

### Features

- **Daemon trust broker.** Local daemon (`emberd`) holds credentials,
  issues scoped time-bound grants, enforces policy, signs Grant
  Receipts. Always-up via macOS LaunchAgent / Linux systemd.
- **Grants — unified primitive.** Credential, token-budget, dollar-budget,
  and compute grants share one `resource_type` + `budget` + `usage` +
  `attestation` shape. `ember grant create / list / show / revoke /
  renew / edit / extend` subcommands. Conditions: rate limits, time
  windows, allowed targets, delegation depth.
- **Composite grants.** Bundle multiple action scopes (`git.push`,
  `gh.pr_create`, `wrangler.deploy`, …) into one approval and one
  receipt. Per-statement metering; cascade revocation kills the chain.
- **Real-time metering + agent self-moderation.** Live token + dollar
  gauges in the dashboard; `on_budget_warning` MCP signal at 80%; auto-
  revocation at exhaustion.
- **Standing grants.** "Approve Always" wiring with auto-delegation,
  policy levels, idle re-lock, and quiet hours.
- **Biometric approval.** macOS LocalAuthentication for the CLI;
  WebAuthn for the dashboard.
- **Hardened sandbox.** Per-session fresh-clone workspace; refused-input
  validation; sandbox-owner verification on exec. Docker
  `no-new-privileges`, read-only rootfs, `cap-drop=ALL`.
- **Signed Grant Receipts.** Every terminated grant emits a durable
  Ed25519-signed JSON record with the approved chain, per-statement
  usage, and verifiable signatures. Exportable via `ember receipt
  export`.
- **Dashboard at `localhost:3141`.** Live grants, audit log, anomaly
  alerts, approval queue, persona inspection. CSRF-protected POST
  endpoints.
- **MCP server (`emberlink-mcp`).** Routes Claude Code / Cursor / other
  MCP-aware agents through the daemon for `request_grant`,
  `use_credential`, `list_grants`. JIT escalation with desktop
  notification.
- **Vault.** XChaCha20-Poly1305 + Argon2id; OS keychain integration
  (macOS Keychain, Linux Secret Service); auto-unseal on daemon start;
  per-keyring service/account configuration.
- **SDKs.** Rust (`emberlink-agent`), TypeScript (`@emberlink/agent`),
  Python (`emberlink-agent`). Same protocol surface; same examples.
- **CLI hygiene.** `ember status` with `--json`; humantime TTL parsing
  (`15m`, `1h`, `3600`); name-or-ID resolution across sandbox/grant/
  persona subcommands; `--config` honored by every subcommand;
  completions and metadata commands.
- **Identity & recovery.** Persona creation, badge issuance / revocation,
  guardian enrollment, badge counter-attestation and dispute, persona-
  scoped badge galleries, authority weighting via graph distance.
- **Offline exchange.** QR encoding of grant links; CLI `ember offer
  create`; offline grant verification.
- **Tauri desktop GUI** with shared data directory.

### Bug fixes

- `ember grant revoke` emits a Grant Receipt instead of silently dropping
  the grant.
- Auth bypass and destructive-state-wipe paths closed.
- Plaintext secrets in SQLite-at-rest encrypted.
- `EMBER_VAULT_PASSPHRASE` environment variable cleared from the process
  environment after read.
- `LocalKeyPair` no longer derives `PartialEq` (timing-attack surface
  removed).
- Daemon dashboard bind failures surface to the user instead of failing
  silently.
- `docker exec` drops `-t` when stdin is not a TTY, fixing sandbox
  invocations from non-interactive contexts.
- `ember init` no longer leaks to the production keyring when
  `EMBER_KEYRING_SERVICE` is set but `--config` is absent.
- rustls ring crypto provider installed before TLS-builder calls,
  fixing relay startup on systems without a default crypto provider.
- macOS Keychain integration verifies the round-trip on add, surfacing
  permission failures at registration time rather than at first use.

[Unreleased]: https://github.com/emberdotlink/emberlink/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/emberdotlink/emberlink/releases/tag/v0.3.0
[0.2.0]: https://github.com/emberdotlink/emberlink/releases/tag/v0.2.0
