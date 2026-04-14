import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type {
  AgentConfig,
  AgentResponse,
  WhoAmIResult,
  GrantInfo,
  RequestGrantParams,
  RequestGrantResult,
  GrantStatusResult,
  UseCredentialParams,
  CredentialResult,
} from './types.js';

export class EmberAgentError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'EmberAgentError';
    this.code = code;
  }
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (reason: EmberAgentError) => void;
};

export class EmberAgent {
  private config: AgentConfig;
  private proc: ChildProcess | null = null;
  private pending: Map<string, PendingRequest> = new Map();
  private counter = 0;

  constructor(config: AgentConfig) {
    this.config = config;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const binary = this.config.binaryPath ?? 'emberlink-agent';
      const args = ['--db', this.config.dbPath, '--persona', this.config.personaId];
      if (this.config.label) {
        args.push('--label', this.config.label);
      }

      const proc = spawn(binary, args, { stdio: ['pipe', 'pipe', 'inherit'] });
      this.proc = proc;

      proc.once('error', (err) => {
        reject(err);
      });

      proc.once('spawn', () => {
        const rl = createInterface({ input: proc.stdout!, crlfDelay: Infinity });
        rl.on('line', (line) => {
          if (!line.trim()) return;
          let msg: AgentResponse;
          try {
            msg = JSON.parse(line) as AgentResponse;
          } catch {
            return;
          }
          const pending = this.pending.get(msg.id);
          if (!pending) return;
          this.pending.delete(msg.id);
          if (msg.error) {
            pending.reject(new EmberAgentError(msg.error.code, msg.error.message));
          } else {
            pending.resolve(msg.result);
          }
        });
        resolve();
      });

      proc.once('close', () => {
        for (const [, p] of this.pending) {
          p.reject(new EmberAgentError('CLOSED', 'agent process closed'));
        }
        this.pending.clear();
        this.proc = null;
      });
    });
  }

  close(): void {
    this.proc?.kill();
    this.proc = null;
  }

  private send<T>(method: string, params?: Record<string, unknown>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      if (!this.proc) {
        reject(new EmberAgentError('NOT_CONNECTED', 'call connect() first'));
        return;
      }
      const id = `req-${++this.counter}`;
      const request = JSON.stringify({ id, method, params: params ?? {} });
      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.proc.stdin!.write(request + '\n');
    });
  }

  whoami(): Promise<WhoAmIResult> {
    return this.send<WhoAmIResult>('whoami');
  }

  listGrants(): Promise<GrantInfo[]> {
    return this.send<GrantInfo[]>('list_grants');
  }

  requestGrant(params: RequestGrantParams): Promise<RequestGrantResult> {
    return this.send<RequestGrantResult>('request_grant', params as Record<string, unknown>);
  }

  grantStatus(grantId: string): Promise<GrantStatusResult> {
    return this.send<GrantStatusResult>('grant_status', { grant_id: grantId });
  }

  useCredential(params: UseCredentialParams): Promise<CredentialResult> {
    return this.send<CredentialResult>('use_credential', params as Record<string, unknown>);
  }
}
