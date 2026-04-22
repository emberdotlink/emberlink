// Basic agent example — connect to ember daemon, request access, use credential.
//
// Run:
//   npx tsx examples/basic-agent.ts
//
// Prerequisites:
//   - ember daemon running (ember daemon start)
//   - a persona created (ember trust create-persona my-agent)
//   - a credential stored (ember storage add github-token)

import * as os from 'node:os';
import * as path from 'node:path';
import { EmberAgentError, SocketTransport } from '../src/index.js';

const SOCKET_PATH = path.join(os.homedir(), '.ember/run/daemon.sock');

// Replace with your agent's persona ID.
const PERSONA_ID = process.env.EMBER_PERSONA_ID ?? 'persona-xxx';
const CREDENTIAL_NAME = process.env.EMBER_CREDENTIAL ?? 'github-token';

async function main(): Promise<void> {
  const transport = new SocketTransport(SOCKET_PATH);

  try {
    await transport.connect();
  } catch (err) {
    console.error(
      `Could not connect to daemon at ${SOCKET_PATH}\nIs it running? Try: ember daemon start`,
      err,
    );
    process.exit(1);
  }

  try {
    // Verify the daemon is reachable.
    const alive = await transport.ping();
    if (!alive) {
      console.error('Daemon did not respond to ping');
      process.exit(1);
    }
    console.log('Connected to ember daemon');

    // Request a grant for the credential.
    // The daemon checks active policy; the human may need to approve.
    const result = (await transport.requestGrant(PERSONA_ID, CREDENTIAL_NAME, 'read')) as Record<
      string,
      unknown
    >;

    const status = result.status as string | undefined;
    console.log('Access decision:', result.decision ?? status);

    if (status === 'approved') {
      const grantId = result.grant_id as string;
      console.log('Grant approved:', grantId);

      // Redeem the grant to retrieve the credential value.
      const credResult = (await transport.useCredential(grantId)) as Record<string, unknown>;
      const credential = String(credResult.credential ?? '');
      const redacted = credential.length > 4 ? credential.slice(0, 4) + '...' : '(empty)';
      console.log('Got credential (redacted):', redacted);
    } else if (status === 'pending') {
      // The human owner must approve the request in the ember UI.
      console.log('Waiting for human approval:', result.approval_id ?? 'unknown');
      console.log('Tip: check the ember UI or run `ember trust approvals`');
    } else {
      console.log('Access denied:', result.reason ?? 'policy');
    }
  } catch (err) {
    if (err instanceof EmberAgentError) {
      console.error(`Daemon error [${err.code}]: ${err.message}`);
    } else {
      console.error('Unexpected error:', err);
    }
    process.exit(1);
  } finally {
    transport.close();
  }
}

main();
