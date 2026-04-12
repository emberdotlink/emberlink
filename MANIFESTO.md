# The Emberlink Manifesto

## What we believe

You don't have an identity online. You have accounts — every one owned by someone else, revocable without your consent.

Your trust relationships are yours. On your device, signed with your keys. You share what you choose, with whom you choose, for as long as you choose. No server reads it. No company revokes it. No validator approves it.

The protocol is open. The software is free. If every Emberlink server went dark, your identity and trust network still work — they live on your device, and anyone near you can verify your signature without asking permission.

Some say you live as long as the last person who remembers you. We believe you should exist as long as anyone in your network can verify your signature.

## What we are building

Emberlink is **programmable trust between humans and machines.**

The grant — scoped, time-bound, revocable delegation of authority from one identity to another — is the fundamental primitive. It works the same whether the recipient is an AI agent, a friend, a service, or a flash coalition of strangers.

The individual is the control point. The individual chooses which persona acts, what each party may know, and can inspect, revoke, or re-issue access at any time.

## Why now

Every company on earth is figuring out how AI agents get access to human data. The current answer is copy-paste and blind trust — pasting secrets into chat windows and hoping for the best.

We are building the authorization layer for the agent era as a general trust protocol, because the same primitive that lets an agent read your credential also lets a friend share a login, a partner pay on your behalf, a guardian recover your identity, or a coalition prove something collectively without revealing individual data.

## The protocol is the commons

Free, open, and permissionless. Forever.

- **The grant protocol.** Structure, signing, exchange, revocation. Open standard.
- **The core libraries.** Identity, event log, disclosure, grants, recovery, sync, trust, storage. Open source, MIT/Apache dual licensed.
- **The relay protocol.** Accept, store, deliver encrypted envelopes. Open spec with reference implementation.
- **The reference applications.** CLI, desktop, browser extension. Open source.

This can never be taken away, locked down, or enshittified.

## The permissionless floor

The protocol works with zero infrastructure. Non-negotiable.

**Layer 0 — Pure P2P.** Two devices, any transport (QR, NFC, Bluetooth, local network, deep link). Grant exchanged. Identities linked. Works offline, air-gapped, with no relay, server, DNS, or blockchain. Nothing to shut down.

**Layer 1 — Relay-assisted async.** Relays hold encrypted envelopes for offline recipients. Anyone can run a relay. Relays never see plaintext. If one goes down, pick another. Identity and trust state remain local.

**Layer 2 — Convenience infrastructure.** Cloud backup, managed relays, push notifications, enterprise tooling. Pay for convenience, never for participation.

## The trust graph is the immune system

Permissionless means anyone can create identities, issue badges, send grants, or publish apps. Bots can too.

We do not solve this by making the protocol permissioned. No proof-of-work. No tokens. No review board.

**The protocol accepts everything. The view is trust-scoped.**

Nothing is blocked or gatekept. But nothing is *visible* to anyone who doesn't trust you. Badges, grants, apps, identities — they exist the moment they're created but surface only if there is a path through the trust graph from viewer to creator.

Spam bot creates a million identities: each is cryptographically valid and invisible — no trust graph connections, no reputation, never surfaces. Real person onboards through a trusted link: recruited into a crew, vouched for, earning badges, visible within hours.

**Creation is permissionless. Visibility is earned.** The trust graph is the immune system at every layer — identity, badges, grants, apps, relay delivery. No central authority. No governance. No tokens.

## Why not a blockchain

Blockchain solves trust between strangers who will never meet. Emberlink solves trust between parties who choose to trust each other. Different problem. Different architecture.

Grants are bilateral — Alice grants Bob access, Alice's signature is the proof, done. No validators needed. Privacy and global consensus are fundamentally opposed.

We get the properties people want from blockchain — immutability, auditability, non-repudiation, censorship resistance — from cryptographic signatures, append-only event logs, and federated relays. Without gas fees, tokens, speculation, or financialization.


## Zero-friction identity

Any transport. Any device. One interaction. Biometric passkey or simpler web-based auth. Identity created. No app install, no email, no password, no terms of service.

The barrier is nothing: a basic smartphone, a network connection, a camera (or NFC, or a shared link). Every client surface — web, mobile, desktop, IoT, extension — upscales the experience. The identity is the same. The protocol is the same.

QR codes, deep links, NFC taps, shared URLs, printed cards — these are all vehicles for the same primitive: a grant link (design) that carries everything needed to onboard in one interaction.

## The app layer

Protocol is the base. Clients are the runtime. Apps are portable WebAssembly payloads.

WASM apps run on top of the identity and trust layer. Each benefits from every identity already in the network. No new account per app. No social graph rebuild. Identity, reputation, and trust relationships travel with you.

Distribution is trust-based: apps are published by identities with reputation from the social graph. Trust graph convergence replaces app store review. The web of trust that secures identity delegation is the same web of trust that filters the app ecosystem.

## Permissionless communities

**Anyone can launch a trust-scoped community with zero infrastructure.** No API key. No partnership. No revenue share. Create an identity, issue badges, distribute onboarding links through any channel.

This works for any entity with a following or a location:

- **Creators** (DJs, bloggers, artists, instructors) own their audience graph cryptographically. Loyalty badges, founding-member badges, attendance badges — all portable across the protocol.
- **Physical locations** (restaurants, bars, venues, shops) are badge issuers. Visit and collect. Pokestops without anyone's permission.
- **Organizers** (political, social, professional) build constituent networks outside platform TOS and algorithmic control.

Every community is a separate hierarchy — its own badges, reputation, and recruitment tree — running on the same protocol, filtered by the same trust graph, fully interoperable. Reputation is portable across every community you belong to.

## The network markets itself

Engaged participants earn the right to physically expand the network. At a reputation threshold, order custom onboarding materials shipped to your door. Users become the distribution network.

Communities pool to claim territory — crowdfund onboarding materials, get permanent founding credit in the badge graph. Marketing cost scales with engagement, not ad spend.

## The escape vector

This is bigger than a company. The protocol is open. Identities belong to their creators. If Emberlink disappeared tomorrow, every community, badge, and trust relationship would still work. Nothing to shut down. Nothing to acquire. Nothing to enshittify.

The protocol outlives all of us. That's the point.

## Design principles

- **The first experience is receiving, not creating.** Someone shares something with you, or you scan a code on a wall. You claim it. You exist. Generosity pulls people in. Reciprocity keeps them.
- **The home screen is your trust network.** Who trusts you with what. Who you trust with what. Active agents. Pending approvals. "Who knows what now?"
- **Sharing is the core interaction.** Scoped, time-bound, one action — as fast as sending a Venmo payment.
- **Revocation is a feature, not a failure.** Every revocation that works builds trust.
- **Recovery is social onboarding.** Adding a guardian is an invitation. Security features are growth features.
- **Agents are a multiplier, not the foundation.** Humans grow the network. Agents make each human 10x more active.
- **The network grows from the ground up.** Not from a launch event. From one person telling another.
- **Creation is permissionless. Visibility is earned.** The trust graph determines what surfaces. Spam, fraud, and noise are invisible, not prevented.

## What composable trust enables

The grant primitive composes:

- **Transitive delegation.** Alice grants Bob disclosure rights. Bob acts within Alice's scope. Alice watches. Alice revokes anytime.
- **Threshold co-authorization.** N-of-M parties must independently authorize before an action proceeds.
- **Conditional autonomous delegation.** Agent gets purchasing authority with spending limits, vendor allow-lists, time windows. Exceeds bounds, enforcement stops it.
- **Flash coalitions.** Strangers pool single-use disclosure grants to collectively prove something without revealing individual data. Grants self-destruct after proof.
- **Proxy actions.** Act on my behalf, within these bounds, and I can see everything you did.

## Commitments

1. The protocol specification will always be open and freely implementable.
2. The core libraries will always be open source under permissive licenses.
3. No identity creation, grant exchange, or trust relationship will ever require our infrastructure.
4. We will never hold plaintext user data on our servers.
5. We will never sell, analyze, or monetize trust relationship metadata.
6. If we cannot sustain the mission, we hand the protocol to a foundation before we compromise it.
