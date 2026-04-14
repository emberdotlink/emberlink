# Emberlink

Programmable trust between humans and machines.

A person saves a credential, clicks Link, and a QR code appears. A second person
scans it with their phone. A passkey ceremony sets up their device on the spot.
They're linked. The credential arrives. The first person can unlink at any time.
No server brokered the exchange. No account was required on either side.

## The link

The link is the primitive. A persistent, inspectable, revocable connection between
two parties — scoped to specific access, time-bound, signed by the issuer, encrypted
for the recipient. Exchange it over any transport: QR, deep link, NFC, local network.
No relay required. No blockchain. No validator.

The same primitive works whether the recipient is a friend, an AI agent, a service,
or a device you own. The issuer stays in control. Unlink anytime. The protocol is open.

## Surfaces

**Extension** — Install in Chrome. Create an identity via passkey. Save a credential.
Click Link to generate a QR code.

**Web** (`ember.link`) — Scans open here. A passkey ceremony sets up the recipient's
device in the browser. The link activates. A card appears showing who linked you,
what access you have, and when it expires.

**Mobile** — Approval surface. When an agent or service requests access, your phone
gets the request. You approve or deny from the lock screen.

**Agent SDK** — TypeScript and Python SDKs, plus an MCP server. AI agents request
named credentials by access type. The check is local. The secret never leaves the
device unless the link allows it.

## Vocabulary

Emberlink uses a deliberate vocabulary stack:

| You see | Protocol calls it |
|---------|------------------|
| link | grant |
| unlink | revoke |
| accept | claim |
| access | scope |
| profile | persona |

User-facing surfaces speak in relationships. Developer APIs speak in protocol.

## Build

```bash
cargo build
cargo test
cargo clippy --workspace
```

## Docs

Brand thesis in [MANIFESTO.md](MANIFESTO.md).

## License

MIT OR Apache-2.0
