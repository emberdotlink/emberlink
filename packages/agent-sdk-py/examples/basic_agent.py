#!/usr/bin/env python3
"""Basic agent example — connect to ember daemon, request access, use credential.

Run:
    python examples/basic_agent.py

Prerequisites:
    - ember daemon running (ember daemon start)
    - a persona created (ember trust create-persona my-agent)
    - a credential stored (ember storage add github-token)
"""

import os
import sys

from emberlink_agent import DaemonError, SocketTransport

SOCKET_PATH = os.path.expanduser("~/.ember/run/daemon.sock")

# Replace with your agent's persona ID.
PERSONA_ID = os.environ.get("EMBER_PERSONA_ID", "persona-xxx")
CREDENTIAL_NAME = os.environ.get("EMBER_CREDENTIAL", "github-token")


def main() -> None:
    try:
        with SocketTransport(SOCKET_PATH) as transport:
            # Verify the daemon is reachable.
            if not transport.ping():
                print("Daemon did not respond to ping", file=sys.stderr)
                sys.exit(1)
            print("Connected to ember daemon")

            # Request a grant for the credential.
            # The daemon checks active policy; the human may need to approve.
            result = transport.request_grant(
                persona_id=PERSONA_ID,
                credential_name=CREDENTIAL_NAME,
                scope="read",
            )

            status = result.get("status")
            print(f"Access decision: {result.get('decision', status)}")

            if status == "approved":
                grant_id = result["grant_id"]
                print(f"Grant approved: {grant_id}")

                # Redeem the grant to retrieve the credential value.
                cred_result = transport.use_credential(PERSONA_ID, CREDENTIAL_NAME)
                credential = str(cred_result.get("credential", ""))
                redacted = credential[:4] + "..." if len(credential) > 4 else "(empty)"
                print(f"Got credential (redacted): {redacted}")

            elif status == "pending":
                # The human owner must approve the request in the ember UI.
                approval_id = result.get("approval_id", "unknown")
                print(f"Waiting for human approval: {approval_id}")
                print("Tip: check the ember UI or run `ember trust approvals`")

            else:
                reason = result.get("reason", "policy")
                print(f"Access denied: {reason}")

    except FileNotFoundError:
        print(
            f"Socket not found: {SOCKET_PATH}\n"
            "Is the ember daemon running? Try: ember daemon start",
            file=sys.stderr,
        )
        sys.exit(1)
    except ConnectionRefusedError:
        print("Daemon refused the connection. Is it running?", file=sys.stderr)
        sys.exit(1)
    except DaemonError as e:
        print(f"Daemon error [{e.code}]: {e.message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
