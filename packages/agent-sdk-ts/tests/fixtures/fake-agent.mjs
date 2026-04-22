#!/usr/bin/env node
/**
 * Fake emberlink-agent binary for unit testing grant_revoked notification handling.
 *
 * Protocol:
 *   - Reads JSON-RPC request lines from stdin
 *   - For method 'whoami': responds with a result
 *   - For method 'emit_revoked': pushes a grant_revoked notification then responds to the caller
 *   - For method 'ping': responds with pong
 */
import { createInterface } from 'node:readline';

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }

  const { id, method } = msg;

  switch (method) {
    case 'whoami':
      write({ id, result: { persona_id: 'persona-test', label: 'Fake Agent' } });
      break;

    case 'emit_revoked': {
      // Push a server-initiated notification (no id), then confirm the call.
      const { grant_id, persona_id } = msg.params ?? {};
      write({ method: 'grant_revoked', params: { grant_id, persona_id } });
      write({ id, result: { ok: true } });
      break;
    }

    case 'ping':
      write({ id, result: { pong: true } });
      break;

    default:
      write({ id, error: { code: 'UNKNOWN_METHOD', message: `unknown method: ${method}` } });
  }
});

function write(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}
