
Summary:
- Role: overview and navigation only
- Decision status: accepted
- Authority state: current
- Implementation status: shipped
- Last reviewed: 2026-05-17

# Emberlink

**The Grant Warden for AI agents.**

*Keep the keys. Grant the action.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Install v0.3.0-rc.1](https://img.shields.io/badge/install-v0.3.0--rc.1-8e44ad.svg)](https://emberlink.sh)

AI agents need authority to do useful work. Most systems hand them a raw token, a broad OAuth scope, or a standing platform permission. Emberlink changes that boundary: the local daemon keeps the credential, and the agent receives a grant that is scoped, time-bound, policy-gated, auditable, and revocable.

## What Emberlink does

- Keeps credentials in the local Warden instead of the agent process tree
- Turns authority into grants with scope, TTL, persona binding, and policy decisions
- Emits signed Receipts so delegated actions have a durable audit artifact
- Exposes one brokered authority surface across multiple agent runtimes

## Install teaser

```bash
cargo install --path crates/emberlink-cli --bin ember
```

Use [QUICKSTART.md](QUICKSTART.md) for the canonical install and first-run path.

## Start here

- [QUICKSTART.md](QUICKSTART.md) — canonical install and onboarding flow
- docs/current-architecture.md — compact current-state architecture map
- CONTEXT.md — terminology, invariants, and architecture vocabulary
- docs/adr-index.md — ADR entrypoint, source order, and lifecycle guidance
- project design notes and release-notes — current release boundary and known scope cuts
- [MANIFESTO.md](MANIFESTO.md) and DESIGN.md — background narrative and UX context

## Current release boundary

The current friendly-drop cohort is three end-to-end Constructs: `ember-gh`, `ember-git`, and `ember-kubectl`. The broader public mirror shape and the v0.3.x boundary are tracked in design and release-notes.

## Contributing

Keep changes focused and include local verification evidence.

## License

Apache-2.0
