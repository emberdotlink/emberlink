# Trust and Verification

Emberlink exposes a **read-only trust inspection surface** today.

That surface is useful for operator evidence and verification work, but it is
not a general trust-management or recovery plane yet.

## Current public truth

For the current public contract:

- `ember trust list` shows the daemon's current trust roots
- `ember trust show <root-id>` drills into one trust root
- `ember trust explain <artifact-path>` explains how a signed artifact verifies
  back to a trust root

This is the current truthful scope of the public trust surface.

## Commands

### List trust roots

```bash
ember trust list
```

This shows:

- the current trust posture (`prod` or `dev`)
- which trust roots are loaded
- whether each root is a `release` or `operator` root

### Show one trust root

```bash
ember trust show <fingerprint-or-prefix>
```

Use this when you already know which root you want and need the detailed
fingerprint/source/posture block.

### Explain a signed artifact

```bash
ember trust explain <artifact-path>
```

This walks a signed artifact back to the trust root that verifies it.

Current artifact kinds:

- `binary_manifest` (default)
- `receipt`
- `workflow_grant`

For non-inline-signature artifacts, you can also provide a sidecar explicitly:

```bash
ember trust explain ./artifact.json --sidecar ./artifact.json.sig
```

## What this surface is for

Use the trust commands when you need to answer questions like:

- which trust roots is the daemon using right now?
- is this host in `dev` or `prod` trust posture?
- which trust root verified this artifact?
- does this signed artifact chain back to a known root?

That makes `trust` part of the current evidence and debugging story, not part
of the day-one onboarding flow.

## What this surface is not

Do not treat `ember trust ...` as:

- a general trust mutation surface
- a backup/restore contract
- a recovery workflow
- a daemon-to-daemon authority bootstrap story

Those larger trust and recovery flows remain outside the current public docs
contract.

## Related pages

- [CLI reference](./cli-reference.md)
- [Receipts and audit](../concepts/receipts-and-audit.md)
- [CLI and troubleshooting](../use/cli-and-troubleshooting.md)
