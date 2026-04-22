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

### `basic_agent.py`

Demonstrates the full `SocketTransport` flow against the running daemon:

- Connect to the Unix socket
- Ping the daemon
- Request a grant for a named credential (`request_grant`)
- Handle the three outcomes: `approved`, `pending`, `denied`
- If approved, redeem the grant (`use_credential`) and print the first four characters

```bash
EMBER_PERSONA_ID=persona-xxx EMBER_CREDENTIAL=github-token \
    python examples/basic_agent.py
```

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `EMBER_PERSONA_ID` | `persona-xxx` | ID of the agent persona |
| `EMBER_CREDENTIAL` | `github-token` | Name of the stored credential |

### `request_credential.py`

Uses the higher-level `EmberAgent` client (wraps the `emberlink-agent` subprocess) to demonstrate `whoami`, `request_grant`, and `grant_status`.

```bash
EMBERLINK_PERSONA=my-agent-persona python examples/request_credential.py
```

## Pending approvals

When a request returns `status: pending` the human owner must approve it before the agent can use the credential. Check the ember UI or run:

```bash
ember trust approvals
```

Once approved, call `request_grant` again (or poll `grant_status`) and proceed with `use_credential`.
