// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';

export type TicketingDestination =
  | {
      readonly type: 'jira';
      readonly url: string;
      readonly email: string;
      readonly apiToken: string;
      readonly projectKey: string;
      readonly issueTypeId: string;
      readonly transitionId?: string;
      readonly priorityMap?: Record<string, string>;
      readonly fieldMappings?: Record<string, string>;
    }
  | {
      readonly type: 'servicenow';
      readonly url: string;
      readonly username: string;
      readonly password: string;
      readonly table: string;
      readonly assignmentGroup?: string;
      readonly stateField?: string;
      readonly stateValues?: { open: string; resolved: string };
    };

export interface TicketingEvent {
  readonly action: 'open' | 'resolve';
  readonly tenantId: string;
  readonly projectId: string;
  readonly scanId: string;
  readonly summary: string;
  readonly description: string;
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  readonly reasons: string[];
  readonly idempotencyKey: string;
  readonly referenceId: string;
  readonly link?: string;
}

interface DispatcherOptions {
  readonly fetch: typeof fetch;
  readonly wait?: (ms: number) => Promise<void>;
  readonly maxAttempts?: number;
  readonly baseDelayMs?: number;
}

const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_BASE_DELAY_MS = 500;

function encodeBasicAuth(username: string, password: string): string {
  return Buffer.from(`${username}:${password}`).toString('base64');
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

function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url
      .replace(/:\/\/[^@]*@/u, '://***@')
      .replace(/\?.*$/u, '')
      .replace(/#.*$/u, '');
  }
}

function mapSeverityToPriority(
  severity: TicketingEvent['severity'],
  customMap?: Record<string, string>
): string {
  const normalized = severity.toLowerCase();

  if (customMap && customMap[normalized]) {
    return customMap[normalized];
  }

  switch (normalized) {
    case 'critical':
      return 'Highest';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    default:
      return 'Info';
  }
}

function buildJiraPayload(destination: Extract<TicketingDestination, { type: 'jira' }>, event: TicketingEvent): ResponseInit & {
  body: string;
  headers: Record<string, string>;
  method: string;
  url: string;
} {
  const priority = mapSeverityToPriority(event.severity, destination.priorityMap);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    Authorization: `Basic ${encodeBasicAuth(destination.email, destination.apiToken)}`,
    'X-Atlassian-Token': 'no-check',
    'Idempotency-Key': event.idempotencyKey
  };

  if (event.action === 'open') {
    const fields: Record<string, unknown> = {
      project: { key: destination.projectKey },
      issuetype: { id: destination.issueTypeId },
      summary: event.summary,
      description: event.description,
      priority: { name: priority },
      labels: ['atlas-sca', event.tenantId]
    };

    if (destination.fieldMappings) {
      for (const [key, value] of Object.entries(destination.fieldMappings)) {
        fields[key] = value;
      }
    }

    fields.reference_id = event.referenceId;
    fields.policy_reasons = event.reasons;
    if (event.link) {
      fields.reference_link = event.link;
    }

    return {
      url: `${destination.url.replace(/\/$/u, '')}/rest/api/3/issue`,
      method: 'POST',
      headers,
      body: JSON.stringify({ fields })
    };
  }

  const transitionId = destination.transitionId ?? '31';
  return {
    url: `${destination.url.replace(/\/$/u, '')}/rest/api/3/issue/${encodeURIComponent(event.referenceId)}/transitions`,
    method: 'POST',
    headers,
    body: JSON.stringify({
      transition: { id: transitionId },
      update: {
        comment: [
          {
            add: {
              body: `Atlas SCA policy status resolved for scan ${event.scanId}.`
            }
          }
        ]
      }
    })
  };
}

function buildServiceNowPayload(
  destination: Extract<TicketingDestination, { type: 'servicenow' }>,
  event: TicketingEvent
): ResponseInit & { body: string; headers: Record<string, string>; method: string; url: string } {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    Authorization: `Basic ${encodeBasicAuth(destination.username, destination.password)}`,
    'Idempotency-Key': event.idempotencyKey
  };

  if (event.action === 'open') {
    const payload: Record<string, unknown> = {
      short_description: event.summary,
      description: event.description,
      severity: event.severity,
      u_reference_id: event.referenceId,
      u_policy_reasons: event.reasons.join(', '),
      category: 'Compliance',
      subcategory: 'Open Source'
    };

    if (destination.assignmentGroup) {
      payload.assignment_group = destination.assignmentGroup;
    }

    if (event.link) {
      payload.u_reference_link = event.link;
    }

    return {
      url: `${destination.url.replace(/\/$/u, '')}/api/now/table/${destination.table}`,
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    };
  }

  const stateField = destination.stateField ?? 'state';
  const stateValues = destination.stateValues ?? { open: '1', resolved: '7' };
  const query = encodeURIComponent(`u_reference_id=${event.referenceId}`);
  const body = JSON.stringify({
    [stateField]: stateValues.resolved,
    close_notes: `Atlas SCA policy status resolved for scan ${event.scanId}.`
  });

  return {
    url: `${destination.url.replace(/\/$/u, '')}/api/now/table/${destination.table}?sysparm_query=${query}`,
    method: 'PATCH',
    headers,
    body
  };
}

async function dispatch(
  destination: TicketingDestination,
  event: TicketingEvent,
  options: Required<DispatcherOptions>
): Promise<void> {
  const request =
    destination.type === 'jira'
      ? buildJiraPayload(destination, event)
      : buildServiceNowPayload(destination, event);

  let attempt = 0;
  let lastError: Error | null = null;
  while (attempt < options.maxAttempts) {
    attempt += 1;
    try {
      const response = await options.fetch(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body
      });

      if (!response.ok) {
        throw new Error(`Ticketing endpoint responded with status ${response.status}`);
      }

      return;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt >= options.maxAttempts) {
        break;
      }
      const delay = options.baseDelayMs * 2 ** (attempt - 1);
      await options.wait(delay);
    }
  }

  const destinationLabel = `${destination.type}:${sanitizeUrl(destination.url)}`;
  throw new Error(`Failed to sync ticket with ${destinationLabel}: ${lastError?.message ?? 'unknown error'}`);
}

export interface TicketingDispatcher {
  sync(event: TicketingEvent): Promise<void>;
}

export function createTicketingDispatcher(
  destinations: TicketingDestination[],
  dispatcherOptions: DispatcherOptions
): TicketingDispatcher {
  const opts: Required<DispatcherOptions> = {
    fetch: dispatcherOptions.fetch,
    wait: dispatcherOptions.wait ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
    maxAttempts: dispatcherOptions.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
    baseDelayMs: dispatcherOptions.baseDelayMs ?? DEFAULT_BASE_DELAY_MS
  };

  const normalizedDestinations = destinations.map((destination) => {
    const context =
      destination.type === 'jira' ? 'Jira destination URL' : 'ServiceNow destination URL';
    const normalizedUrl = requireHttpsUrl(destination.url, context);
    return { ...destination, url: normalizedUrl } satisfies TicketingDestination;
  });

  return {
    async sync(event: TicketingEvent): Promise<void> {
      if (normalizedDestinations.length === 0) {
        return;
      }

      await Promise.all(normalizedDestinations.map((destination) => dispatch(destination, event, opts)));
    }
  };
}
