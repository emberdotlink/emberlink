import { execSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { EmberAgent, EmberAgentError } from '../src/client.js';

const REPO_ROOT = resolve(process.cwd(), '../..');
const BINARY_PATH = resolve(REPO_ROOT, 'target/debug/emberlink-agent');
const FIXTURE_DAEMON_PATH = resolve(
  REPO_ROOT,
  'target/debug/examples/ember_sdk_fixture_daemon',
);
const TEST_CREDENTIAL_NAME = 'github-token';
const TEST_CREDENTIAL_VALUE = 'ghp_fixture_secret';

type FixtureReady = {
  socket_path: string;
  persona_id: string;
  credential_name: string;
};

function binaryAvailable(path: string): boolean {
  try {
    execSync(`test -x "${path}"`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

async function spawnFixtureDaemon(tmpDir: string): Promise<{
  proc: ChildProcess;
  ready: FixtureReady;
}> {
  const socketPath = `/tmp/ember-sdk-ts-${process.pid}-${Date.now()}.sock`;
  const proc = spawn(
    FIXTURE_DAEMON_PATH,
    [
      '--socket',
      socketPath,
      '--persona-name',
      'sdk-ts-agent',
      '--credential-name',
      TEST_CREDENTIAL_NAME,
      '--credential-value',
      TEST_CREDENTIAL_VALUE,
    ],
    { stdio: ['ignore', 'pipe', 'inherit'] },
  );

  const ready = await new Promise<FixtureReady>((resolveReady, reject) => {
    let output = '';

    proc.once('error', reject);
    proc.once('close', (code) => {
      reject(new Error(`fixture daemon exited before readiness (code=${code})`));
    });

    proc.stdout!.on('data', (chunk: Buffer) => {
      output += chunk.toString();
      const newline = output.indexOf('\n');
      if (newline === -1) {
        return;
      }
      const line = output.slice(0, newline).trim();
      if (!line) {
        return;
      }
      try {
        resolveReady(JSON.parse(line) as FixtureReady);
      } catch (err) {
        reject(err);
      }
    });
  });

  return { proc, ready };
}

const liveDaemonSkipReason =
  binaryAvailable(BINARY_PATH) && binaryAvailable(FIXTURE_DAEMON_PATH)
    ? undefined
    : `binaries not built — run: cargo build -p emberlink-agent && cargo build -p ember-daemon --example ember_sdk_fixture_daemon`;

describe('emberlink-agent integration (live daemon)', { skip: liveDaemonSkipReason }, () => {
  let tmpDir: string;
  let dbPath: string;
  let agent: EmberAgent;
  let fixtureProc: ChildProcess;
  let fixtureReady: FixtureReady;

  before(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'emberlink-agent-live-'));
    dbPath = join(tmpDir, 'test.db');
    const fixture = await spawnFixtureDaemon(tmpDir);
    fixtureProc = fixture.proc;
    fixtureReady = fixture.ready;
    agent = new EmberAgent({
      binaryPath: BINARY_PATH,
      dbPath,
      personaId: fixtureReady.persona_id,
      label: 'Integration Test Agent',
      daemonSocket: fixtureReady.socket_path,
    });
    await agent.connect();
  });

  after(() => {
    agent.close();
    fixtureProc.kill('SIGTERM');
    if (existsSync(fixtureReady.socket_path)) {
      rmSync(fixtureReady.socket_path, { force: true });
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test('whoami returns persona info', async () => {
    const result = await agent.whoami();
    assert.equal(result.persona_id, fixtureReady.persona_id);
    assert.equal(result.label, 'Integration Test Agent');
  });

  test('listGrants returns an array', async () => {
    const grants = await agent.listGrants();
    assert.ok(Array.isArray(grants));
  });

  test('requestGrant auto-approves against the live daemon fixture', async () => {
    const result = await agent.requestGrant({
      scope: 'repo:read',
      resource_id: fixtureReady.credential_name,
      reason: 'integration test',
    });
    assert.equal(result.status, 'approved');
    assert.ok(result.request_id.startsWith('grant-'));
  });

  test('grantStatus resolves an active grant after approval', async () => {
    const granted = await agent.requestGrant({
      scope: 'repo:read',
      resource_id: fixtureReady.credential_name,
      reason: 'status integration test',
    });
    const status = await agent.grantStatus(granted.request_id);
    assert.equal(status.status, 'active');
    assert.ok('grant_id' in status);
    assert.equal(status.grant_id, granted.request_id);
  });

  test('useCredential returns the live daemon secret', async () => {
    const granted = await agent.requestGrant({
      scope: 'repo:read',
      resource_id: fixtureReady.credential_name,
      reason: 'credential integration test',
    });
    const result = await agent.useCredential({
      grant_id: granted.request_id,
      credential_name: fixtureReady.credential_name,
    });
    assert.equal(result.status, 'ok');
    assert.equal(result.credential.value, TEST_CREDENTIAL_VALUE);
    assert.equal(result.credential.grant_id, granted.request_id);
  });
});

const helperSkipReason = binaryAvailable(BINARY_PATH)
  ? undefined
  : 'binary not built — run: cargo build -p emberlink-agent';

describe('emberlink-agent integration (no daemon)', { skip: helperSkipReason }, () => {
  test('requestGrant fails closed when no daemon is reachable', async () => {
    const originalHome = process.env.HOME;
    const isolatedHome = mkdtempSync(join(tmpdir(), 'emberlink-agent-nodaemon-'));
    process.env.HOME = isolatedHome;

    const agent = new EmberAgent({
      binaryPath: BINARY_PATH,
      dbPath: join(isolatedHome, 'test.db'),
      personaId: 'persona-no-daemon',
    });

    try {
      await agent.connect();
      await assert.rejects(
        () =>
          agent.requestGrant({
            scope: 'repo:read',
            resource_id: 'github-token',
            reason: 'no daemon proof',
          }),
        (err: unknown) => {
          assert.ok(err instanceof EmberAgentError);
          assert.equal((err as EmberAgentError).code, 'DAEMON_UNAVAILABLE');
          return true;
        },
      );
    } finally {
      agent.close();
      process.env.HOME = originalHome;
      rmSync(isolatedHome, { recursive: true, force: true });
    }
  });
});
