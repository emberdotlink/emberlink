# The Emberlink Manifesto

## What we believe

You don't have an identity online. You have accounts — every one owned by someone else, revocable without your consent.

Your trust relationships are yours. On your device, signed with your keys. You share what you choose, with whom you choose, for as long as you choose. No server reads it. No company revokes it. No validator approves it.

The protocol is open. The software is free. If every Emberlink server went dark, your identity and trust network still work — they live on your device, and anyone near you can verify your signature without asking permission.

Some say you live as long as the last person who remembers you. We believe you should exist as long as anyone in your network can verify your signature.

## What we are building

Emberlink is **the Grant Warden for AI agents** — and, beneath that, the general pattern of **programmable trust between humans and machines**. The Warden guards the moment of delegation: it keeps the credentials the agent must never see, issues scoped and time-bound *grants* for the work the agent actually needs to do, enforces policy, requires human approval when required, binds authority to a persona, tracks the delegation chain, revokes instantly (including cascades to sub-agents), and emits a signed **Grant Receipt** as durable proof of what was delegated and what the agent did.

Agents should not get credentials. Agents should get grants.

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

## Can't, not won't

The difference between "can't" and "won't" is architectural. "Won't" is a policy — it changes under pressure, under a subpoena, under a board vote. "Can't" is structure. Build systems that are incapable of the thing you don't want, and you never have to trust anyone's promise not to do it (design).

The protocol has no censorship surface. No transaction blocklist. No admin kill switch on participation. No central server that could be compelled to block a grant exchange. It is structurally incapable of preventing a valid interaction between two identities, the same way TCP is structurally incapable of refusing a packet based on its contents.

Accountability still exists — on the individual. Each participant is responsible for their own transactions and who they transact with, mediated by their trust graph. The protocol doesn't enforce that. The protocol *can't* enforce that. That's the point.

## The escape vector

This is bigger than a company. The protocol is open. Identities belong to their creators. If Emberlink disappeared tomorrow, every community, badge, and trust relationship would still work. Nothing to shut down. Nothing to acquire. Nothing to enshittify.

The protocol outlives all of us. That's the point.

## Design principles

- **The first experience is receiving, not creating.** Someone links you to something, or you scan a code on a wall. You accept it. You exist. Generosity pulls people in. Reciprocity keeps them.
- **The home screen is your trust network.** Who's linked to you. Who you're linked to. Active agents. Pending approvals. "Who knows what now?"
- **Linking is the core interaction.** Scoped, time-bound, one action — as fast as sending a Venmo payment. A link is a persistent connection, not a one-time transfer.
- **Unlinking is a feature, not a failure.** Every unlink that works builds trust.
- **Recovery is social onboarding.** Adding a guardian is an invitation. Security features are growth features.
- **Agents are a multiplier, not the foundation.** Humans grow the network. Agents make each human 10x more active.
- **The network grows from the ground up.** Not from a launch event. From one person telling another.
- **Creation is permissionless. Visibility is earned.** The trust graph determines what surfaces. Spam, fraud, and noise are invisible, not prevented.

## What composable trust enables

The grant primitive composes:

- **Transitive delegation.** Alice grants Bob disclosure rights. Bob acts within Alice's scope. Alice watches. Alice revokes anytime.
- **Threshold co-authorization.** N-of-M parties must independently authorize before an action proceeds.
- **Conditional autonomous delegation.** Agent gets purchasing authority with spending limits, vendor allow-lists, time windows. Exceeds bounds, enforcement stops it.
- **Just-in-time escalation.** Request elevated access, a designated approver signs approval from their phone, the grant is time-bound and auto-revokes. The same guardian pattern that secures recovery secures production database access, household spending limits, and WiFi password sharing (design).
- **Rotating credentials.** Grants reference living credentials that rotate on a schedule. Active grantees get the new version. Revoked grantees don't. Your WiFi password rotates weekly; your approved guests always have the current one.
- **Flash coalitions.** Strangers pool single-use disclosure grants to collectively prove something without revealing individual data. Grants self-destruct after proof.
- **Proxy actions.** Act on my behalf, within these bounds, and I can see everything you did.

## Commitments

1. The protocol specification will always be open and freely implementable.
2. The core libraries will always be open source under permissive licenses.
3. No identity creation, grant exchange, or trust relationship will ever require our infrastructure.
4. We will never hold plaintext user data on our servers.
5. We will never sell, analyze, or monetize trust relationship metadata.
6. If we cannot sustain the mission, we hand the protocol to a foundation before we compromise it.

## The Agent Economy

Agents are no longer tools. They are actors — autonomous, persistent, operating on your behalf across services, APIs, and data you care about. They need credentials. They need authorization. They need audit trails.

The current answer is dangerous and binary. Give the agent your API key and hope it doesn't abuse it. Or give it nothing, and it can't do the work. Full access or useless. There is no middle ground.

This is the gap Ember closes.

**The problem with full credentials is not capability — it's accountability.** When an agent holds your AWS key, it holds your AWS key. No scope. No expiry. No record of what it touched. If it goes wrong, you find out after. If it goes very wrong, you find out from your cloud bill.

Ember's position is not a permissions system bolted onto agents. It is the human's trust broker in the agent economy.

The relationship is: human approves, agent executes. Not once, at setup. Continuously, at the boundary of what was authorized. The agent never holds raw credentials — it holds a grant. The grant says what the agent may do, for how long, under what conditions. The grant can be revoked from your phone in three seconds.

**Four principles that are not negotiable:**

1. Agents never hold raw credentials. They hold scoped, time-bound grants that reference living credentials. The credentials rotate. The agent gets the current version only while the grant is active.
2. Every credential access is auditable. Not "logged somewhere." Logged in an append-only event record that the human can read, export, and verify. The agent cannot lie about what it did.
3. Humans approve, agents execute. Elevated access requires a human signature. Not a checkbox at setup — a real-time approval from the phone of whoever owns the resource.
4. Trust is earned, not assumed. A new agent starts narrow: read-only, time-boxed, limited scope. It earns wider access through a track record of behavior. Trust widens with demonstrated reliability, not with a prompt that says "trust me."

**The vision is agents that are as trustworthy as good employees** — not because they are inherently trustworthy, but because the infrastructure makes betrayal impossible and accountability automatic. You don't trust your accountant because you've looked into their soul. You trust them because there are records, limits, consequences, and visibility.

That is what Ember builds for agents. The trust infrastructure that makes the agent economy safe to participate in.

---

## The product

The ember daemon is this philosophy made concrete.

It runs on your device. It holds your keys. It knows your policies. When an agent asks for something, your daemon is the one who answers.

```
$ ember daemon start

  ember daemon v0.2.0
  The trust layer for AI agents

  Socket:    ~/.ember/run/daemon.sock
  Dashboard: http://localhost:3141
```

Every credential encrypted. Every access scoped and time-bound. Every action logged. Every decision yours.

Not "trust us." Trust yourself.
