# Python SDK examples

## Prerequisites

Before running any example you need:

1. **ember daemon running**

   ```bash
   ember daemon start
   ```

2. **A persona for your agent**

   ```bash
   ember trust create-persona my-agent
   # copy the printed persona ID
   ```

3. **A credential stored under a name the agent will request**

   ```bash
   ember storage add github-token
   # paste or type the token value when prompted
   ```

4. **Python package installed** (editable install from repo root, or `pip install emberlink-agent`)

   ```bash
   pip install -e packages/agent-sdk-py
   ```

## Examples

### `request_credential.py`

Uses the public `EmberAgent` helper client. The Python package does not expose
its own direct socket transport; it spawns `emberlink-agent`, which then talks
to the local daemon for daemon-backed methods.

The example demonstrates:

- `whoami`
- `request_grant(scope, resource_id=...)`
- `grant_status`
- `use_credential`

```bash
EMBERLINK_PERSONA=my-agent-persona \
EMBERLINK_CREDENTIAL=github-token \
python examples/request_credential.py
```

Optional:

```bash
EMBERLINK_DAEMON_SOCKET=/path/to/daemon.sock \
EMBERLINK_PERSONA=my-agent-persona \
python examples/request_credential.py
```

## Pending approvals

When a request returns `status: pending` the human owner must approve it before the agent can use the credential. Check the ember UI or run:

```bash
ember trust approvals
```

Once approved, call `request_grant` again (or poll `grant_status`) and proceed with `use_credential`.
