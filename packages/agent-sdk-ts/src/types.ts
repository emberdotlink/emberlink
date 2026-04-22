export interface AgentConfig {
  binaryPath?: string;
  dbPath: string;
  personaId: string;
  label?: string;
}

export interface AgentRequest {
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

export interface AgentResponse<T = unknown> {
  id: string;
  result?: T;
  error?: { code: string; message: string };
}

export interface WhoAmIResult {
  persona_id: string;
  label?: string;
}

export interface GrantInfo {
  grant_id: string;
  issuer_id: string;
  capability: string;
  status: string;
  expires_at?: number;
}

export interface RequestGrantParams {
  [key: string]: unknown;
  scope: string;
  resource_id?: string;
  duration_secs?: number;
  reason?: string;
}

export interface RequestGrantResult {
  request_id: string;
  status: string;
}

export interface GrantStatusResult {
  grant_id: string;
  status: string;
}

export interface UseCredentialParams {
  [key: string]: unknown;
  grant_id: string;
  credential_id: string;
}

export interface CredentialResult {
  status: string;
  credential: {
    value: string;
    scope: string;
    grant_id: string;
  };
}

/** Server-initiated notification pushed by the daemon when a grant is revoked. */
export interface GrantRevokedNotification {
  grant_id: string;
  persona_id: string;
}

/** A JSON-RPC notification (no `id` field) pushed from the daemon. */
export interface AgentNotification {
  method: string;
  params: unknown;
}
