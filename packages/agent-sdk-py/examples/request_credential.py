# Request a credential from Emberlink.
# Run: python examples/request_credential.py
# Requires: emberlink-agent binary in PATH and a provisioned database.

import os
import sys
from emberlink_agent import AgentConfig, EmberAgent, EmberAgentError

config = AgentConfig(
    db_path=os.environ.get("EMBERLINK_DB", "./emberlink.db"),
    persona_id=os.environ.get("EMBERLINK_PERSONA", "my-agent-persona"),
    daemon_socket=os.environ.get("EMBERLINK_DAEMON_SOCKET"),
)

try:
    with EmberAgent(config) as agent:
        me = agent.whoami()
        print("Connected as:", me.persona_id)

        grant = agent.request_grant(
            scope="repo:read",
            resource_id=os.environ.get("EMBERLINK_CREDENTIAL", "github-token"),
            reason="streaming session",
        )
        print("Grant request submitted:", grant.request_id, "— status:", grant.status)

        status = agent.grant_status(grant.request_id)
        print("Grant status:", status.status)

except FileNotFoundError:
    print("Could not start emberlink-agent. Is the binary in your PATH?", file=sys.stderr)
    sys.exit(1)
except EmberAgentError as e:
    print(f"Agent error [{e.code}]: {e.message}", file=sys.stderr)
    sys.exit(1)
