export interface AgentConfig {
  binaryPath?: string;
  dbPath: string;
  personaId: string;
  label?: string;
  daemonSocket?: string;
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

export interface PendingGrantStatusResult {
  request_id: string;
  status: string;
}

export interface ActiveGrantStatusResult {
  grant_id: string;
  status: string;
  issuer_id?: string;
  capability?: string;
  expires_at?: number;
}

export type GrantStatusResult = PendingGrantStatusResult | ActiveGrantStatusResult;

export interface UseCredentialParams {
  [key: string]: unknown;
  grant_id: string;
  credential_name: string;
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

/**
 * Budget axis values — must match the Rust BudgetAxis enum wire form.
 * Values are lowercase snake_case as serialized on the wire.
 */
export type BudgetAxis = 'tokens' | 'cents' | 'requests' | 'wall_clock_secs';

/**
 * Threshold band that triggered this notification.
 * "warning" fires at 80% and 95% crossings; "exhausted" fires at 100%.
 */
export type ThresholdBand = 'warning' | 'exhausted';

/** Payload pushed by the daemon when a Statement's budget crosses a warning threshold (80%, 95%). */
export interface BudgetWarningNotification {
  grant_id: string;
  statement_sid: string;
  axis: BudgetAxis;
  used: number;
  budget: number;
  percent: number;
  threshold_band: 'warning';
}

/** Payload pushed by the daemon when a Statement's budget is fully exhausted (100%). */
export interface BudgetExhaustedNotification {
  grant_id: string;
  statement_sid: string;
  axis: BudgetAxis;
  used: number;
  budget: number;
  percent: number;
  threshold_band: 'exhausted';
}

/** A JSON-RPC notification (no `id` field) pushed from the daemon. */
export interface AgentNotification {
  method: string;
  params: unknown;
}
