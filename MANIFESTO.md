# The Emberlink Manifesto

## What we believe

AI agents are no longer tools. They are **actors** — autonomous, persistent, operating on your behalf across services, APIs, and data you care about. They need authority. They need accountability. They need limits.

The current answer is dangerous and binary. Hand the agent your API key and hope it doesn't go wrong. Or give it nothing, and it can't do the work. Full access or useless. There is no middle ground.

**Agents should not get credentials. Agents should get grants.**

A grant is the fundamental primitive: scoped, time-bound, persona-bound, budgeted, revocable delegation of authority from one identity to another. The recipient gets authority to *act*, not the key. When the grant ends, a signed **Grant Receipt** records who delegated what to whom, what was narrowed, what the agent did, and when it ended. Durable. Exportable. Verifiable.

The same primitive that lets an AI agent hit your GitHub token also lets a friend share a login, a partner pay on your behalf, a guardian recover your identity, or a coalition prove something collectively without revealing individual data. We are building the authorization layer for the agent era *as a general trust protocol*, because the shape is general.

Emberlink's Grant protocol is intentionally small and generic; the same envelope spans credentials, payments, sessions, compute, time, and future authority surfaces — extensible by adding ResourceType variants, not by shipping plugins.

Credentials are the doorway. Delegated authority is the category. Signed receipts are the proof.

## What we are building

Emberlink is **the Grant Warden for AI agents**.

The Warden is a local-first daemon that guards the moment of delegation. It holds the credentials the agent must never see. It issues scoped, time-bound *grants* for the work the agent actually needs to do. It enforces policy. It requires human approval when policy demands. It binds authority to a persona. It tracks the delegation chain. It revokes instantly — including cascade revocation to sub-agents that inherited a narrower grant. It emits a signed Grant Receipt as durable proof of every terminated grant.

The individual is the control point. The individual chooses which persona acts, what each party may know, and can inspect, revoke, or re-issue access at any time.

## Why now

Every company on earth is figuring out how AI agents get access to human and corporate data. The current default is copy-paste and blind trust — pasting secrets into chat windows and hoping for the best. Standing tokens with broad scope. OAuth grants that never expire. Platform permissions impossible to revoke cleanly.

One prompt injection, one supply-chain bite, one runaway retry loop, and the credential is gone or the bill is $10K.

The agent economy needs the same trust infrastructure that organizations built for human employees forty years ago — but reshaped for actors that operate at machine speed, persist across sessions, and compose into delegation chains. That infrastructure does not exist yet. We are building it.

## The agent economy is the wedge

**The problem with full credentials is not capability — it's accountability.** When an agent holds your AWS key, it holds your AWS key. No scope. No expiry. No record of what it touched. If it goes wrong, you find out after. If it goes very wrong, you find out from your cloud bill.

Emberlink's position is not a permissions system bolted onto agents. It is **the human's trust broker in the agent economy**.

The relationship is: human approves, agent executes. Not once, at setup. Continuously, at the boundary of what was authorized. The agent never holds raw credentials — it holds a grant. The grant says what the agent may do, for how long, under what conditions. The grant can be revoked from your phone in three seconds.

**Five principles that are not negotiable:**

0. **Every authorized action is verifiable.** The receipt — not the credential boundary — is the durable artifact. Anyone the operator chooses can confirm the chain of authority outside our infrastructure, with no vendor in the loop.
1. **Agents never hold raw credentials.** They hold scoped, time-bound grants that reference living credentials. The credentials rotate. The agent gets the current version only while the grant is active.
2. **Every credential access is auditable.** Not "logged somewhere." Logged in an append-only event record that the human can read, export, and verify. The agent cannot lie about what it did.
3. **Humans approve, agents execute.** Elevated access requires a human signature. Not a checkbox at setup — a real-time approval from the phone of whoever owns the resource.
4. **Trust is earned, not assumed.** A new agent starts narrow: read-only, time-boxed, limited scope. It earns wider access through a track record of behavior. Trust widens with demonstrated reliability, not with a prompt that says "trust me."

The vision is agents that are as trustworthy as good employees — not because they are inherently trustworthy, but because the infrastructure makes betrayal impossible and accountability automatic. You don't trust your accountant because you've looked into their soul. You trust them because there are records, limits, consequences, and visibility.

## What composable trust enables

The grant primitive composes:

- **Transitive delegation.** Alice grants Bob disclosure rights. Bob acts within Alice's scope. Alice watches. Alice revokes anytime.
- **Threshold co-authorization.** N-of-M parties must independently authorize before an action proceeds.
- **Conditional autonomous delegation.** Agent gets purchasing authority with spending limits, vendor allow-lists, time windows. Exceeds bounds, enforcement stops it.
- **Just-in-time escalation.** Request elevated access, a designated approver signs approval from their phone, the grant is time-bound and auto-revokes. The same guardian pattern that secures recovery secures production database access, household spending limits, and WiFi password sharing.
- **Rotating credentials.** Grants reference living credentials that rotate on a schedule. Active grantees get the new version. Revoked grantees don't.
- **Cascade revocation.** Sub-agents inherit a narrower grant. Revoking the parent kills the whole chain in one action.
- **Proxy actions.** Act on my behalf, within these bounds, and I can see everything you did.

Same primitive, same UX, same audit. Whether the recipient is an AI agent, a friend, a service, or a flash coalition of strangers.

## The protocol is the commons

Free, open, and permissionless. Forever.

- **The grant protocol.** Structure, signing, exchange, revocation. Open standard.
- **The core libraries.** Identity, event log, grants, vault, recovery, sync, trust, storage. Open source, Apache-2.0.
- **The relay protocol.** Accept, store, deliver encrypted envelopes. Open spec with reference implementation.
- **The reference applications.** CLI (`ember`), daemon (`emberd`),
  proxy/runtime mediation, sandbox, dashboard, MCP server, and SDKs. All open
  source.

This can never be taken away, locked down, or enshittified.

## Can't, not won't

The difference between *can't* and *won't* is architectural. *Won't* is a policy — it changes under pressure, under a subpoena, under a board vote. *Can't* is structure. Build systems that are incapable of the thing you don't want, and you never have to trust anyone's promise not to do it.

The protocol has no censorship surface. No transaction blocklist. No admin kill switch on participation. No central server that could be compelled to block a grant exchange. It is structurally incapable of preventing a valid interaction between two identities, the same way TCP is structurally incapable of refusing a packet based on its contents.

Accountability still exists — on the individual. Each participant is responsible for their own transactions and who they transact with, mediated by their trust graph. The protocol doesn't enforce that. The protocol *can't* enforce that. That's the point.

## Why not a blockchain

Blockchain solves trust between strangers who will never meet. Emberlink solves trust between parties who choose to trust each other. Different problem. Different architecture.

Grants are bilateral — Alice grants Bob access, Alice's signature is the proof, done. No validators needed. Privacy and global consensus are fundamentally opposed.

We get the properties people want from blockchain — immutability, auditability, non-repudiation, censorship resistance — from cryptographic signatures, append-only event logs, and federated relays. Without gas fees, tokens, speculation, or financialization.

## The protocol works without us

The protocol works with zero infrastructure. Non-negotiable.

**Layer 0 — Pure P2P.** Two devices, any transport (QR, NFC, Bluetooth, local network, deep link). Grant exchanged. Identities linked. Works offline, air-gapped, with no relay, server, DNS, or blockchain. Nothing to shut down.

**Layer 1 — Relay-assisted async.** Relays hold encrypted envelopes for offline recipients. Anyone can run a relay. Relays never see plaintext. If one goes down, pick another. Identity and trust state remain local.

**Layer 2 — Convenience infrastructure.** Cloud backup, managed relays, push notifications, and organizational tooling can make the protocol easier to operate, but they are not required for participation.

If every Emberlink server went dark, your identity, your grants, your trust network, and your receipt history still work — they live on your device, and anyone you've delegated to can verify your signature without asking permission.

## The long-arc thesis

The grant primitive does not stop at AI agents. The same protocol that brokers authority between a human and a coding agent can broker authority between humans, between organizations, between strangers who choose to coordinate without a platform.

That long-arc — *permissionless communities* where creators own their audience graph, where physical locations issue badges, where flash coalitions prove things collectively without revealing individuals — is preserved at the protocol level but is **not the current focus**. The agent economy is the wedge. The general protocol is the foundation that wedge sits on. We will build the consumer expansion when the Grant Warden path for agents is real, deployed, and proven.

Until then: developer-first, agent-first, daemon-first.

## The escape vector

This is bigger than a company. The protocol is open. Identities belong to their creators. If Emberlink Systems disappeared tomorrow, every grant, every receipt, every trust relationship would still work. Nothing to shut down. Nothing to acquire. Nothing to enshittify.

The protocol outlives all of us. That's the point.

## Commitments

1. The protocol specification will always be open and freely implementable.
2. The core libraries will always be open source under permissive licenses.
3. No identity creation, grant exchange, or trust relationship will ever require our infrastructure.
4. We will never hold plaintext user data on our servers.
5. We will never sell, analyze, or monetize trust relationship metadata.
6. If we cannot sustain the mission, we hand the protocol to a foundation before we compromise it.

---

## The product

The ember daemon is this philosophy made concrete.

It runs on your device. It holds your keys. It knows your policies. When an agent asks for something, your daemon is the one who answers.

```
$ ember status

  ember daemon v0.3.x
  The Grant Warden for AI agents

  Status: running
  Vault:  locked or unlocked by local policy
  Audit:  receipt history available locally
```

Every credential encrypted. Every access scoped and time-bound. Every action logged. Every grant signed. Every termination receipted.

Not "trust us." Trust yourself.

Install path and integration guide: [QUICKSTART.md](QUICKSTART.md).
