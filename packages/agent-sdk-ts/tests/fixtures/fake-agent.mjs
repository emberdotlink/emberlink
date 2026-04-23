#!/usr/bin/env node
/**
 * Fake emberlink-agent binary for unit testing notification handling.
 *
 * Protocol:
 *   - Reads JSON-RPC request lines from stdin
 *   - For method 'whoami': responds with a result
 *   - For method 'emit_revoked': pushes a grant_revoked notification then responds to the caller
 *   - For method 'emit_budget_warning': pushes a budget.warning notification then responds
 *   - For method 'emit_budget_exhausted': pushes a budget.exhausted notification then responds
 *   - For method 'emit_malformed_budget': pushes a budget.warning with missing fields then responds
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
      const { grant_id, persona_id } = msg.params ?? {};
      write({ method: 'grant_revoked', params: { grant_id, persona_id } });
      write({ id, result: { ok: true } });
      break;
    }

    case 'emit_budget_warning': {
      const p = msg.params ?? {};
      write({
        method: 'budget.warning',
        params: {
          grant_id: p.grant_id ?? 'grant-budget-001',
          statement_sid: p.statement_sid ?? 'stmt-001',
          axis: p.axis ?? 'tokens',
          used: p.used ?? 16000,
          budget: p.budget ?? 20000,
          percent: p.percent ?? 80,
          threshold_band: 'warning',
        },
      });
      write({ id, result: { ok: true } });
      break;
    }

    case 'emit_budget_exhausted': {
      const p = msg.params ?? {};
      write({
        method: 'budget.exhausted',
        params: {
          grant_id: p.grant_id ?? 'grant-budget-001',
          statement_sid: p.statement_sid ?? 'stmt-001',
          axis: p.axis ?? 'tokens',
          used: p.used ?? 20000,
          budget: p.budget ?? 20000,
          percent: p.percent ?? 100,
          threshold_band: 'exhausted',
        },
      });
      write({ id, result: { ok: true } });
      break;
    }

    case 'emit_malformed_budget': {
      // Push a budget.warning with missing required fields to exercise error handling.
      write({ method: 'budget.warning', params: {} });
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
