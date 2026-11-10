// SPDX-License-Identifier: MIT

import { setTimeout as delay } from 'node:timers/promises';

type SupportedSiem = 'splunk' | 'sentinel' | 'elastic';

export interface SiemDestination {
  readonly type: SupportedSiem;
  readonly url: string;
  readonly token?: string;
  readonly dataset?: string;
}

export interface SiemEvent {
  readonly type: 'scan.completed' | 'scan.failed';
  readonly tenantId: string;
  readonly projectId: string | null;
  readonly scanId: string;
  readonly policyResult: 'pass' | 'warn' | 'fail' | 'error';
  readonly totalVulnerabilities: number;
  readonly downgradedByVex: number;
  readonly timestamp: string;
  readonly metadata?: Record<string, unknown>;
}

export interface SiemDispatcher {
  publish(event: SiemEvent): Promise<void>;
}

interface DispatcherOptions {
  readonly fetch?: typeof fetch;
  readonly wait?: (ms: number) => Promise<void>;
  readonly maxAttempts?: number;
  readonly baseDelayMs?: number;
}

const DEFAULT_ATTEMPTS = 3;
const DEFAULT_BACKOFF_MS = 500;

function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

function requireHttpsUrl(url: string, context: string): string {
  let parsed: URL;

  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${context} must be a valid HTTPS URL.`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`${context} must use HTTPS.`);
  }

  parsed.username = '';
  parsed.password = '';
  return parsed.toString();
}

function validateEvent(event: SiemEvent): void {
  if (!event.tenantId) {
    throw new Error('SIEM event tenantId is required.');
  }

  if (!event.scanId) {
    throw new Error('SIEM event scanId is required.');
  }

  if (!event.type) {
    throw new Error('SIEM event type is required.');
  }
}

function buildHeaders(destination: SiemDestination): HeadersInit {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };

  if (destination.token && destination.token.length > 0) {
    const prefix =
      destination.type === 'splunk'
        ? 'Splunk '
        : destination.type === 'sentinel'
          ? 'SharedKey '
          : 'ApiKey ';
    headers.Authorization = `${prefix}${destination.token}`;
  }

  return headers;
}

function buildBody(destination: SiemDestination, event: SiemEvent): string {
  const basePayload = {
    event_type: event.type,
    tenant_id: event.tenantId,
    project_id: event.projectId,
    scan_id: event.scanId,
    policy_result: event.policyResult,
    vulnerabilities_total: event.totalVulnerabilities,
    vulnerabilities_downgraded: event.downgradedByVex,
    timestamp: event.timestamp,
    metadata: event.metadata ?? {},
    dataset: destination.dataset ?? null
  } as const;

  if (destination.type === 'splunk') {
    return JSON.stringify({ event: basePayload });
  }

  if (destination.type === 'sentinel') {
    return JSON.stringify({ records: [basePayload] });
  }

  return JSON.stringify(basePayload);
}

async function defaultWait(ms: number): Promise<void> {
  await delay(ms);
}

export function createSiemDispatcher(
  destinations: ReadonlyArray<SiemDestination>,
  options: DispatcherOptions = {}
): SiemDispatcher {
  const fetchImpl = options.fetch ?? fetch;
  const waitImpl = options.wait ?? defaultWait;
  const maxAttempts = Math.max(1, options.maxAttempts ?? DEFAULT_ATTEMPTS);
  const baseDelayMs = Math.max(100, options.baseDelayMs ?? DEFAULT_BACKOFF_MS);
  const normalizedDestinations = destinations.map((destination) => {
    const context = `SIEM destination (${destination.type}) URL`;
    const normalizedUrl = requireHttpsUrl(destination.url, context);
    return { ...destination, url: normalizedUrl } satisfies SiemDestination;
  });

  async function sendWithRetry(destination: SiemDestination, body: string, headers: HeadersInit): Promise<void> {
    let attempt = 0;
    let lastError: unknown;

    while (attempt < maxAttempts) {
      attempt += 1;
      try {
        const response = await fetchImpl(destination.url, {
          method: 'POST',
          headers,
          body
        });

        if (response.ok) {
          return;
        }

        const responseText = await response.text().catch(() => '');
        lastError = new Error(
          `SIEM destination ${destination.type} returned ${response.status}: ${responseText.slice(0, 256)}`
        );
      } catch (error) {
        lastError = error;
      }

      if (attempt < maxAttempts) {
        const delayMs = baseDelayMs * attempt;
        await waitImpl(delayMs);
      }
    }

    const sanitizedUrl = sanitizeUrl(destination.url);
    const message =
      lastError instanceof Error ? `${lastError.message}` : `Unknown error: ${String(lastError ?? 'unknown')}`;
    throw new Error(
      `SIEM dispatch to ${destination.type} (${sanitizedUrl}) failed after ${maxAttempts} attempts: ${message}`
    );
  }

  return {
    async publish(event: SiemEvent): Promise<void> {
      validateEvent(event);

      const deliveryTasks = normalizedDestinations.map((destination) => {
        const headers = buildHeaders(destination);
        const body = buildBody(destination, event);
        return sendWithRetry(destination, body, headers);
      });

      await Promise.all(deliveryTasks);
    }
  } satisfies SiemDispatcher;
}
