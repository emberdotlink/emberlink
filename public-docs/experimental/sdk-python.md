# Python SDK

The Python package exists, but the broader SDK/headless story is still
under-specified relative to the rest of the current product surface. Treat this
page as **experimental** and not as a recommended default integration path.

## Package

```bash
pip install emberlink-agent
```

Requires Python 3.10 or later.

## Current shape

The package currently exposes a narrow daemon-backed client for:

- daemon-backed grant requests
- grant-status polling
- credential use under active grants
- background notification handlers for revoke and budget events

Those are real package surfaces, but they are **not** the same thing as the
larger SDK design language that appears in older planning docs.

## Narrow current truth

- the package is a client around the `emberlink-agent` helper binary; a direct
  daemon `SocketTransport` surface is not yet publicly shipped
- it is narrower than the larger “session open / broker resolve /
  three-mode escalation” SDK design story
- it is not the recommended default public integration surface today

If you use it, treat it as a package-level contract you are auditing directly,
not as the settled public Emberlink integration contract.

## Fail-closed behavior

This package is intentionally fail-closed:

- if `connect()` fails, no request proceeds
- if the helper exits, in-flight work fails
- the SDK does not fall back to an alternate credential path

## Honesty boundary

The package may be useful for advanced evaluation, but the broader SDK/headless
story is still less trustworthy than the launcher and MCP surfaces.

Current proof bar:

- live Python package tests now run against a real latest-daemon fixture
- no-daemon helper flows fail closed with `DAEMON_UNAVAILABLE`
- `request_grant` must name the credential via `resource_id` for daemon policy routing

If you want the current most-supported operator path, prefer the daemon-backed
CLI and launcher story first.

If you are deciding whether the SDK is the right fit, start with
[Choose an integration surface](../build/choosing-an-integration-surface.md).

## Source of truth

The package-local README remains the detailed source for the package as it
exists today:

- `packages/agent-sdk-py/README.md`
