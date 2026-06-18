# Grants and Approvals

Emberlink's core product surface is delegated authority.

That means the current public CLI contract includes two closely related lanes:

- **grants** for scoped delegated authority
- **approvals** for actions that require human confirmation instead of
  auto-approval

## Grants

The current public grant surface includes:

```bash
ember grant create ...
ember grant list
ember grant revoke <grant-id>
ember grant delegate <grant-id> ...
ember grant extend <grant-id> ...
ember grant expire <grant-id>
ember grant budget <grant-id> ...
```

Current truth:

- on the installed path, these run through the daemon
- `grant create` preserves the current budget, rate-limit, time-window,
  delegation-depth, and standing-parent shape
- `grant list` is the broader operator view, not the narrower MCP/runtime
  grant listing contract

## Approvals

The current public approval surface includes:

```bash
ember approval list
ember approve <request-id>
ember deny <request-id>
ember narrow <request-id> ...
```

Use approvals when an agent action or delegated workflow lands in the
approval-required lane instead of the auto-approved lane.

## How these two surfaces fit together

The current product model is:

- grants define delegated authority
- approvals resolve higher-risk or policy-gated authority requests
- receipts and audit records preserve evidence about what happened

That is why these commands belong together conceptually even though they are
different CLI groups.

## What this surface is for

Use these commands when you need to:

- inspect delegated authority on the current host
- revoke or narrow authority
- resolve approval queues raised by agent actions
- extend or budget an existing delegated grant

## What this surface is not

Do not treat the current public docs contract as promising:

- a broader recovery plane
- daemon-to-daemon authority transfer
- a fully stabilized team-scale workflow beyond the current local daemon path

Those larger authority-management stories are still narrower than the core
local operator surface documented here.

## Related pages

- [The Grant Warden Model](../concepts/grant-warden.md)
- [Receipts and audit](../concepts/receipts-and-audit.md)
- [CLI reference](./cli-reference.md)
