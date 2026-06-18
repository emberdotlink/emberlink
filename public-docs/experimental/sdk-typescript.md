# TypeScript SDK

The TypeScript package exists, but the broader SDK/headless story is still
under-specified relative to the rest of the current product surface. Treat this
page as **experimental** and not as a recommended default integration path.

## Package

```bash
npm install @emberlink/agent
```

Requires Node.js 18 or later.

## Current shape

The current package exposes a narrow daemon-backed client for:

- connecting to Emberlink
- requesting grants
- polling grant status
- using credentials under active grants
- receiving grant-revoked and budget notifications

Those are real package surfaces, but they are **not** the same as the broader
SDK design story described in older planning docs.

## Narrow current truth

- the package is a client around the `emberlink-agent` helper binary; a direct
  daemon `SocketTransport` surface is not yet publicly shipped
- it is narrower than the larger “session open / broker resolve /
  three-mode escalation” SDK design language that appears in older ADRs
- it is not the recommended default public integration surface today

If you use it, treat it as a package-level contract you are auditing directly,
not as the settled public product contract for Emberlink integrations.

## Fail-closed behavior

This package is intentionally fail-closed:

- if `connect()` fails, requests do not proceed
- if the helper exits, in-flight work fails
- the SDK does not substitute an alternate credential path

## Important honesty boundary

The package may be useful for advanced evaluation, but the broader SDK/headless
story is still less trustworthy than the launcher and MCP surfaces.

Current proof bar:

- live TypeScript package tests now run against a real latest-daemon fixture
- no-daemon helper flows fail closed with `DAEMON_UNAVAILABLE`
- `requestGrant` must name the credential via `resource_id` for daemon policy routing

If you want the most stable public path today, prefer:

- `ember init --for claude`
- `ember claude`
- `ember codex` if Codex is your native agent surface
- `emberlink-mcp`

If you are deciding whether the SDK is the right fit, start with
[Choose an integration surface](../build/choosing-an-integration-surface.md).

## Source of truth

The package-local README remains the detailed source for the package as it
exists today:

- `packages/agent-sdk-ts/README.md`
