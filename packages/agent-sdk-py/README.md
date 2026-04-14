# emberlink-agent

Python SDK for the Emberlink agent authorization protocol.

## Prerequisites

The `emberlink-agent` binary must be installed before using this SDK.

### Download from GitHub Releases

Download the binary for your platform from:

```
https://github.com/emberdotlink/emberlink/releases/latest
```

Available targets:

| File | Platform |
|------|----------|
| `emberlink-agent-x86_64-apple-darwin.tar.gz` | macOS Intel |
| `emberlink-agent-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `emberlink-agent-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 |
| `emberlink-agent-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 |

Extract and place on PATH:

```bash
tar xzf emberlink-agent-*.tar.gz
chmod +x emberlink-agent
sudo mv emberlink-agent /usr/local/bin/
```

### Build from source

```bash
cargo install --path crates/emberlink-agent
```

### Verify

```bash
emberlink-agent --version
```

## Usage

```python
from emberlink_agent import EmberAgent, AgentConfig

config = AgentConfig(db_path="./emberlink.db", persona_id="your-id")
with EmberAgent(config) as agent:
    me = agent.whoami()
    grants = agent.list_grants()
```

## Examples

See [`examples/request_credential.py`](examples/request_credential.py) for a full flow: connect → whoami → request_grant → check status.

## Configuration

The `emberlink-agent` binary must be in your PATH or specified via `binary_path`.

```python
config = AgentConfig(
    db_path="./emberlink.db",
    persona_id="your-id",
    binary_path="/usr/local/bin/emberlink-agent",
)
```

## API

### `EmberAgent(config: AgentConfig)`

Constructor. Call `connect()` to start the subprocess, or use as a context manager.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `whoami()` | `WhoAmIResult` | Active persona identity |
| `list_grants()` | `list[GrantInfo]` | All grants for this persona |
| `request_grant(scope, resource_id?, duration_secs?, reason?)` | `RequestGrantResult` | Request a new grant |
| `grant_status(grant_id)` | `GrantStatusResult` | Status of a specific grant |
| `use_credential(grant_id, credential_id)` | `UseCredentialResult` | Retrieve a credential value |

### Error handling

```python
from emberlink_agent import EmberAgent, AgentConfig, EmberAgentError

config = AgentConfig(db_path="./emberlink.db", persona_id="your-id")
with EmberAgent(config) as agent:
    try:
        result = agent.use_credential("grant-123", "cred-456")
    except EmberAgentError as e:
        print(e.code)     # e.g. "GRANT_INACTIVE", "NOT_FOUND"
        print(e.message)
```

Error codes: `UNKNOWN_METHOD`, `INVALID_PARAMS`, `STORE_ERROR`, `NOT_FOUND`, `GRANT_INACTIVE`, `NO_CREDENTIAL`
