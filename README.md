
Summary:
- Role: overview and navigation only
- Decision status: accepted
- Authority state: current
- Implementation status: shipped
- Last reviewed: 2026-05-20

# Emberlink

**The Grant Warden for AI agents.**

*Keep the keys. Grant the action.*

Public docs: <https://docs.ember.link>

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release%20source%20mirror-8e44ad.svg)](project design notes)

AI agents need authority to do useful work. Most systems hand them a raw token, a broad OAuth scope, or a standing platform permission. Emberlink changes that boundary: the local daemon keeps the credential, and the agent receives a grant that is scoped, time-bound, policy-gated, auditable, and revocable.

## What Emberlink does

- Keeps credentials in the local Warden instead of the agent process tree
- Turns authority into grants with scope, TTL, persona binding, and policy decisions
- Emits signed Receipts so delegated actions have a durable audit artifact
- Exposes one brokered authority surface across multiple agent runtimes

## Release posture

- The repository may be public before the first broadly supported build.
- `v0.3.0` remains the friendly-preview build gate, not the general-release gate.
- `v0.3.1` is the first planned public supported build and install funnel.

The canonical boundary for those milestones lives in design, [QUICKSTART.md](QUICKSTART.md), and release-notes.

## Install

The curated public source mirror may be open before the first self-serve
supported install lane. `v0.3.0` remains an invite-only friendly-preview
build, and `v0.3.1` is the first planned public supported build.

If you are in the named friendly cohort, use the signed preview artifact
and onboarding notes provided with your invite. Once `ember` is on your
`PATH`, run:

```bash
ember init --for claude-code
```

If `ANTHROPIC_API_KEY` is present when you run init, Ember stores it as
`anthropic-key` and `ember claude-code` can reuse a brokered Claude runtime
grant. If not, Claude's own upstream auth remains ambient and Ember still
brokers the Git/GitHub/tool side of the session. To move onto the brokered
runtime lane later, rerun `ember init --for claude-code` with
`ANTHROPIC_API_KEY` exported or run `ember vault add --name anthropic-key`.

If you're evaluating from the public source mirror today, use the
source-build path:

```bash
cargo install --locked --path crates/emberlink-cli --bin ember
ember init --for claude-code
```

Use [QUICKSTART.md](QUICKSTART.md) for the current pre-release install and
first-run path.

## Start here

- [docs.ember.link](https://docs.ember.link) — curated public docs site
- [QUICKSTART.md](QUICKSTART.md) — canonical install and onboarding flow
- docs/current-architecture.md — compact current-state architecture map
- CONTEXT.md — terminology, invariants, and architecture vocabulary
- docs/adr-index.md — ADR entrypoint, source order, and lifecycle guidance
- project design notes and release-notes — current release boundary and known scope cuts
- [MANIFESTO.md](MANIFESTO.md) and DESIGN.md — background narrative and UX context

## Current release boundary

The current friendly-drop cohort is three end-to-end Constructs: `ember-gh`, `ember-git`, and `ember-kubectl`. The source mirror may be public before the first public supported build; the current milestone split is tracked in design and release-notes.

## Contributing

Keep changes focused and include local verification evidence.

## License

Apache-2.0
