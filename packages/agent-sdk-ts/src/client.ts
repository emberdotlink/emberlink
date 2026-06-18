import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type {
  AgentConfig,
  AgentResponse,
  AgentNotification,
  BudgetExhaustedNotification,
  BudgetWarningNotification,
  GrantRevokedNotification,
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

  /**
   * Called when the daemon pushes a `grant_revoked` notification.
   * Assign this before calling `connect()` to ensure no notifications are missed.
   */
  onGrantRevoked?: (params: GrantRevokedNotification) => void;

  /**
   * Called when the daemon pushes a `budget.warning` notification (80% or 95% threshold crossed).
   * Assign this before calling `connect()` to ensure no notifications are missed.
   */
  onBudgetWarning?: (params: BudgetWarningNotification) => void;

  /**
   * Called when the daemon pushes a `budget.exhausted` notification (100% threshold crossed).
   * Assign this before calling `connect()` to ensure no notifications are missed.
   */
  onBudgetExhausted?: (params: BudgetExhaustedNotification) => void;

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
      if (this.config.daemonSocket) {
        args.push('--daemon-socket', this.config.daemonSocket);
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
          let msg: AgentResponse | AgentNotification;
          try {
            msg = JSON.parse(line) as AgentResponse | AgentNotification;
          } catch {
            return;
          }
          if ((msg as AgentResponse).id != null) {
            const resp = msg as AgentResponse;
            const pending = this.pending.get(resp.id);
            if (!pending) return;
            this.pending.delete(resp.id);
            if (resp.error) {
              pending.reject(new EmberAgentError(resp.error.code, resp.error.message));
            } else {
              pending.resolve(resp.result);
            }
          } else {
            const notif = msg as AgentNotification;
            try {
              if (notif.method === 'grant_revoked') {
                this.onGrantRevoked?.(notif.params as GrantRevokedNotification);
              } else if (notif.method === 'budget.warning') {
                this.onBudgetWarning?.(notif.params as BudgetWarningNotification);
              } else if (notif.method === 'budget.exhausted') {
                this.onBudgetExhausted?.(notif.params as BudgetExhaustedNotification);
              }
            } catch {
              // Callback exceptions must not crash the line handler.
            }
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
    const { credential_name, ...rest } = params;
    return this.send<CredentialResult>('use_credential', {
      ...rest,
      credential_id: credential_name,
    });
  }
}
