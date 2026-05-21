// Request a credential from Emberlink.
// Run: npx tsx examples/request-credential.ts
// Requires: emberlink-agent binary in PATH and a provisioned database.

import { EmberAgent, EmberAgentError } from '../src/index.js';

const agent = new EmberAgent({
  dbPath: process.env.EMBERLINK_DB ?? './emberlink.db',
  personaId: process.env.EMBERLINK_PERSONA ?? 'my-agent-persona',
  daemonSocket: process.env.EMBERLINK_DAEMON_SOCKET,
});

try {
  await agent.connect();
} catch (err) {
  console.error('Could not start emberlink-agent. Is the binary in your PATH?', err);
  process.exit(1);
}

const me = await agent.whoami();
console.log('Connected as:', me.persona_id);

const grant = await agent.requestGrant({
  scope: 'repo:read',
  resource_id: process.env.EMBERLINK_CREDENTIAL ?? 'github-token',
  reason: 'streaming session',
});
console.log('Grant request submitted:', grant.request_id, '— status:', grant.status);

const status = await agent.grantStatus(grant.request_id);
console.log('Grant status:', status.status);

agent.close();
