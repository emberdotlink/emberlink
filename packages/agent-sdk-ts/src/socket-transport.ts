import * as net from 'node:net';
import { createInterface } from 'node:readline';
import { EmberAgentError } from './client.js';
import type { AgentResponse } from './types.js';

export interface DaemonRequest {
  id: string;
  method: string;
  params: unknown;
}

export interface DaemonResponse {
  id: string;
  result?: unknown;
  error?: { code: string; message: string };
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (reason: EmberAgentError) => void;
};

export class SocketTransport {
  private socket: net.Socket | null = null;
  private pending: Map<string, PendingRequest> = new Map();
  private counter = 0;

  constructor(private socketPath: string) {}

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ path: this.socketPath });
      this.socket = socket;

      socket.once('connect', () => {
        const rl = createInterface({ input: socket, crlfDelay: Infinity });
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

      socket.once('error', (err) => {
        reject(err);
      });

      socket.once('close', () => {
        for (const [, p] of this.pending) {
          p.reject(new EmberAgentError('CLOSED', 'socket closed'));
        }
        this.pending.clear();
        this.socket = null;
      });
    });
  }

  send(method: string, params?: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new EmberAgentError('NOT_CONNECTED', 'call connect() first'));
        return;
      }
      const id = String(++this.counter);
      const request: DaemonRequest = { id, method, params: params ?? null };
      this.pending.set(id, { resolve, reject });
      this.socket.write(JSON.stringify(request) + '\n');
    });
  }

  async ping(): Promise<boolean> {
    const result = await this.send('ping');
    return (result as { pong?: boolean })?.pong === true;
  }

  async requestGrant(
    personaId: string,
    credentialName: string,
    scope: string,
    ttlSecs?: number,
  ): Promise<unknown> {
    return this.send('request_grant', {
      persona_id: personaId,
      credential_name: credentialName,
      scope,
      ttl_secs: ttlSecs,
    });
  }

  async useCredential(personaId: string, credentialName: string): Promise<unknown> {
    return this.send('use_credential', { persona_id: personaId, credential_name: credentialName });
  }

  async requestAccess(personaId: string, action: string, resource: string): Promise<unknown> {
    return this.send('request_access', { persona_id: personaId, action, resource });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }
}
