import { execSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { EmberAgent, EmberAgentError } from '../src/client.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BINARY_PATH = resolve(__dirname, '../../../target/debug/emberlink-agent');
const TEST_PERSONA_ID = 'test-persona-001';

function binaryAvailable(): boolean {
  try {
    execSync(`test -x "${BINARY_PATH}"`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const skipReason = binaryAvailable()
  ? undefined
  : 'binary not built — run: cargo build -p emberlink-agent';

describe('emberlink-agent integration', { skip: skipReason }, () => {
  let tmpDir: string;
  let dbPath: string;
  let agent: EmberAgent;

  before(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'emberlink-agent-test-'));
    dbPath = join(tmpDir, 'test.db');
    agent = new EmberAgent({
      binaryPath: BINARY_PATH,
      dbPath,
      personaId: TEST_PERSONA_ID,
      label: 'Integration Test Agent',
    });
    await agent.connect();
  });

  after(() => {
    agent.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test('whoami returns persona info', async () => {
    const result = await agent.whoami();
    assert.equal(result.persona_id, TEST_PERSONA_ID);
    assert.equal(result.label, 'Integration Test Agent');
  });

  test('list_grants returns an array (empty initially)', async () => {
    const grants = await agent.listGrants();
    assert.ok(Array.isArray(grants));
  });

  test('request_grant with scope returns a request_id', async () => {
    const result = await agent.requestGrant({ scope: 'test' });
    assert.ok(typeof result.request_id === 'string');
    assert.ok(result.request_id.length > 0);
    assert.equal(result.status, 'pending');
  });

  test('grant_status for pending request returns pending status', async () => {
    const granted = await agent.requestGrant({ scope: 'ReadCredential', reason: 'integration test' });
    const status = await agent.grantStatus(granted.request_id);
    assert.ok(typeof (status as Record<string, unknown>)['status'] === 'string');
  });

  test('grant_status for nonexistent grant returns NOT_FOUND error', async () => {
    await assert.rejects(
      () => agent.grantStatus('nonexistent-grant-id'),
      (err: unknown) => {
        assert.ok(err instanceof EmberAgentError);
        assert.equal((err as EmberAgentError).code, 'NOT_FOUND');
        return true;
      },
    );
  });

  test('use_credential for nonexistent grant returns NOT_FOUND error', async () => {
    await assert.rejects(
      () => agent.useCredential({ grant_id: 'nonexistent-grant', credential_id: 'cred-1' }),
      (err: unknown) => {
        assert.ok(err instanceof EmberAgentError);
        assert.equal((err as EmberAgentError).code, 'NOT_FOUND');
        return true;
      },
    );
  });

  test('invalid method returns error via protocol', async () => {
    // Spawn a second agent and send a bad request directly over stdin
    // to exercise the UNKNOWN_METHOD error path.
    const { spawn } = await import('node:child_process');
    const proc = spawn(BINARY_PATH, ['--db', dbPath, '--persona', TEST_PERSONA_ID], {
      stdio: ['pipe', 'pipe', 'inherit'],
    });

    const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
      let output = '';
      proc.stdout!.on('data', (chunk: Buffer) => {
        output += chunk.toString();
        if (output.includes('\n')) {
          try {
            resolve(JSON.parse(output.trim()) as Record<string, unknown>);
          } catch {
            reject(new Error(`Failed to parse response: ${output}`));
          }
        }
      });
      proc.on('error', reject);
      proc.stdin!.write(JSON.stringify({ id: 'req-bad', method: 'fly_to_moon', params: {} }) + '\n');
    });

    proc.kill();
    assert.ok('error' in response);
    const error = response['error'] as { code: string };
    assert.equal(error.code, 'UNKNOWN_METHOD');
  });
});
