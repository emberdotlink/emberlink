/**
 * Unit tests for budget.warning and budget.exhausted server-initiated notification handling.
 *
 * Uses the same fake agent binary (tests/fixtures/fake-agent.mjs) as the grant_revoked tests.
 * The fake binary supports 'emit_budget_warning', 'emit_budget_exhausted', and
 * 'emit_malformed_budget' trigger methods.
 */
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { EmberAgent } from '../src/client.js';
import type { BudgetWarningNotification, BudgetExhaustedNotification } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(__dirname, '..', '..');
const FAKE_BINARY = resolve(PACKAGE_ROOT, 'tests', 'fixtures', 'fake-agent.mjs');

function makeAgent(): EmberAgent {
  return new EmberAgent({
    binaryPath: FAKE_BINARY,
    dbPath: '/fake/db.sqlite',
    personaId: 'persona-test',
    label: 'Test',
  });
}

type SendHelper = {
  send<T>(method: string, params?: Record<string, unknown>): Promise<T>;
};

describe('budget.warning notification demux (unit)', () => {
  const agents: EmberAgent[] = [];

  afterEach(() => {
    for (const a of agents) {
      a.close();
    }
    agents.length = 0;
  });

  test('onBudgetWarning callback fires with correct payload', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    const received: BudgetWarningNotification[] = [];
    agent.onBudgetWarning = (params) => received.push(params);

    const result = await (agent as unknown as SendHelper).send<{ ok: boolean }>(
      'emit_budget_warning',
      {
        grant_id: 'grant-abc',
        statement_sid: 'stmt-session',
        axis: 'tokens',
        used: 16000,
        budget: 20000,
        percent: 80,
      },
    );

    assert.equal(result.ok, true);
    assert.equal(received.length, 1);
    assert.deepEqual(received[0], {
      grant_id: 'grant-abc',
      statement_sid: 'stmt-session',
      axis: 'tokens',
      used: 16000,
      budget: 20000,
      percent: 80,
      threshold_band: 'warning',
    });
  });

  test('onBudgetExhausted callback fires with correct payload', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    const received: BudgetExhaustedNotification[] = [];
    agent.onBudgetExhausted = (params) => received.push(params);

    const result = await (agent as unknown as SendHelper).send<{ ok: boolean }>(
      'emit_budget_exhausted',
      {
        grant_id: 'grant-abc',
        statement_sid: 'stmt-session',
        axis: 'tokens',
        used: 20000,
        budget: 20000,
        percent: 100,
      },
    );

    assert.equal(result.ok, true);
    assert.equal(received.length, 1);
    assert.deepEqual(received[0], {
      grant_id: 'grant-abc',
      statement_sid: 'stmt-session',
      axis: 'tokens',
      used: 20000,
      budget: 20000,
      percent: 100,
      threshold_band: 'exhausted',
    });
  });

  test('pending request promise registry is not corrupted by a budget.warning notification', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    const received: BudgetWarningNotification[] = [];
    agent.onBudgetWarning = (params) => received.push(params);

    // Issue emit_budget_warning: daemon pushes notification first, then responds.
    const triggerPromise = (agent as unknown as SendHelper).send<{ ok: boolean }>(
      'emit_budget_warning',
      { grant_id: 'grant-xyz', statement_sid: 'stmt-001', axis: 'cents', used: 95, budget: 100, percent: 95 },
    );

    // Concurrently issue whoami to interleave in the pending map.
    const whoamiPromise = agent.whoami();

    const [triggerResult, whoamiResult] = await Promise.all([triggerPromise, whoamiPromise]);

    assert.equal(received.length, 1);
    assert.equal(received[0]!.grant_id, 'grant-xyz');
    assert.equal(received[0]!.threshold_band, 'warning');

    assert.equal(triggerResult.ok, true);
    assert.equal(whoamiResult.persona_id, 'persona-test');
    assert.equal(whoamiResult.label, 'Fake Agent');
  });

  test('pending request promise registry is not corrupted by a budget.exhausted notification', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    const received: BudgetExhaustedNotification[] = [];
    agent.onBudgetExhausted = (params) => received.push(params);

    const triggerPromise = (agent as unknown as SendHelper).send<{ ok: boolean }>(
      'emit_budget_exhausted',
      { grant_id: 'grant-xyz', statement_sid: 'stmt-001', axis: 'requests', used: 100, budget: 100, percent: 100 },
    );

    const whoamiPromise = agent.whoami();

    const [triggerResult, whoamiResult] = await Promise.all([triggerPromise, whoamiPromise]);

    assert.equal(received.length, 1);
    assert.equal(received[0]!.threshold_band, 'exhausted');
    assert.equal(triggerResult.ok, true);
    assert.equal(whoamiResult.persona_id, 'persona-test');
  });

  test('budget.warning callback exception does not crash the line handler', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    agent.onBudgetWarning = (_params) => {
      throw new Error('intentional error from budget warning callback');
    };

    // Despite the callback throwing, the send promise must resolve normally.
    await assert.doesNotReject(async () => {
      await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_budget_warning', {});
    });

    // The handler must still be functional — whoami should succeed.
    const whoami = await agent.whoami();
    assert.equal(whoami.persona_id, 'persona-test');
  });

  test('budget.exhausted callback exception does not crash the line handler', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    agent.onBudgetExhausted = (_params) => {
      throw new Error('intentional error from budget exhausted callback');
    };

    await assert.doesNotReject(async () => {
      await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_budget_exhausted', {});
    });

    const whoami = await agent.whoami();
    assert.equal(whoami.persona_id, 'persona-test');
  });

  test('no onBudgetWarning handler — budget.warning notification does not throw', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    // Neither callback is set. Budget notifications should be silently dropped.
    await assert.doesNotReject(async () => {
      await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_budget_warning', {});
    });
  });

  test('no onBudgetExhausted handler — budget.exhausted notification does not throw', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    await assert.doesNotReject(async () => {
      await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_budget_exhausted', {});
    });
  });

  test('malformed budget.warning payload is delivered to onBudgetWarning as-is', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    const received: BudgetWarningNotification[] = [];
    agent.onBudgetWarning = (params) => received.push(params);

    await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_malformed_budget', {});

    // Callback still fires — SDK delivers what the daemon sent; validation is caller's responsibility.
    assert.equal(received.length, 1);
    // The payload will have no fields set (empty params from fake binary).
    assert.ok(typeof received[0] === 'object');
  });

  test('grant_revoked and budget callbacks are independent — no cross-fire', async () => {
    const agent = makeAgent();
    agents.push(agent);
    await agent.connect();

    let revokedCount = 0;
    let warningCount = 0;
    let exhaustedCount = 0;

    agent.onGrantRevoked = () => { revokedCount++; };
    agent.onBudgetWarning = () => { warningCount++; };
    agent.onBudgetExhausted = () => { exhaustedCount++; };

    // Fire each notification type once.
    await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_revoked', {
      grant_id: 'g1',
      persona_id: 'p1',
    });
    await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_budget_warning', {});
    await (agent as unknown as SendHelper).send<{ ok: boolean }>('emit_budget_exhausted', {});

    assert.equal(revokedCount, 1);
    assert.equal(warningCount, 1);
    assert.equal(exhaustedCount, 1);
  });
});
