// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  buildServer,
  type Database,
  type JobQueue,
  type RedisConnection
} from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';

vi.mock('prom-client', () => {
  class MockMetric {
    startTimer() {
      return () => {};
    }

    labels() {
      return this;
    }

    set() {}

    inc() {}

    reset() {}
  }

  class MockRegistry {
    metrics() {
      return Promise.resolve('');
    }

    get contentType() {
      return 'text/plain';
    }
  }

  return {
    Counter: MockMetric,
    Gauge: MockMetric,
    Histogram: MockMetric,
    Registry: MockRegistry,
    collectDefaultMetrics: () => {}
  } satisfies Record<string, unknown>;
}, { virtual: true });

const TEST_VERSION = '0.0.0-test';
const TENANT_ID = 'tenant-123';

function createMetricsStub(): Metrics {
  return {
    registry: {
      metrics: () => Promise.resolve(''),
      contentType: 'text/plain'
    },
    queueDepthGauge: { set: () => {} },
    scanDurationHistogram: { startTimer: () => () => {} },
    noticeBuildHistogram: { startTimer: () => () => {} },
    webhookOutcomeCounter: { inc: () => {} },
    feedImportCounter: { inc: () => {} },
    vexStateGauge: { set: () => {} },
    purgeDurationHistogram: { startTimer: () => () => {} }
  } satisfies Metrics;
}

function createQueueMock(): JobQueue {
  return {
    add: vi.fn().mockResolvedValue(undefined)
  } as JobQueue;
}

function createRedisMock(): RedisConnection {
  return {
    ping: vi.fn().mockResolvedValue('PONG')
  } satisfies RedisConnection;
}

const encodeCursor = (createdAt: string, id: string) =>
  Buffer.from(JSON.stringify({ created_at: createdAt, id }), 'utf8').toString('base64url');

describe('GET /v1/audit/events', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>> | null = null;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    db = {
      query: vi.fn().mockResolvedValue({ rows: [] })
    } as { query: ReturnType<typeof vi.fn> } & Database;

    queue = createQueueMock();
    redis = createRedisMock();
    metrics = createMetricsStub();

    const auth = createAuthMocks(TENANT_ID, ['Admin', 'Auditor']);
    authHeaders = auth.headers;

    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: auth.lookupApiKey,
      licenseStatusProvider: createLicenseStatusProvider()
    });
  });

  afterEach(async () => {
    if (app) {
      await app.close();
      app = null;
    }
    vi.restoreAllMocks();
  });

  it('returns audit events with pagination metadata and next cursor', async () => {
    const rows = [
      {
        id: 'event-newest',
        tenant_id: TENANT_ID,
        project_id: 'project-1',
        scan_id: 'scan-1',
        actor_type: 'api_key',
        actor_identifier: 'key-1',
        event_type: 'project.created',
        event_payload: { project_id: 'project-1' },
        event_hash: 'hash-new',
        created_at: '2024-07-02T10:00:00.000Z'
      },
      {
        id: 'event-middle',
        tenant_id: TENANT_ID,
        project_id: null,
        scan_id: null,
        actor_type: 'api_key',
        actor_identifier: 'key-1',
        event_type: 'scan.enqueued',
        event_payload: { scan_id: 'scan-2' },
        event_hash: 'hash-mid',
        created_at: '2024-07-01T10:00:00.000Z'
      },
      {
        id: 'event-oldest',
        tenant_id: TENANT_ID,
        project_id: null,
        scan_id: null,
        actor_type: 'system',
        actor_identifier: null,
        event_type: 'system.heartbeat',
        event_payload: {},
        event_hash: 'hash-old',
        created_at: '2024-06-30T10:00:00.000Z'
      }
    ];

    db.query.mockResolvedValueOnce({ rows });

    if (!app) {
      throw new Error('server not initialised');
    }

    const response = await app.inject({
      method: 'GET',
      url: '/v1/audit/events',
      headers: authHeaders,
      query: { limit: 2 }
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      data: Array<Record<string, unknown>>;
      pagination: { limit: number; next_cursor: string | null };
    };

    expect(body.data).toHaveLength(2);
    expect(body.data[0]?.id).toBe('event-newest');
    expect(body.data[1]?.id).toBe('event-middle');
    expect(body.pagination.limit).toBe(2);
    expect(typeof body.pagination.next_cursor).toBe('string');

    const decoded = JSON.parse(
      Buffer.from(body.pagination.next_cursor ?? '', 'base64url').toString('utf8')
    ) as { created_at: string; id: string };
    expect(decoded).toMatchObject({ id: 'event-oldest' });

    const queryCall = db.query.mock.calls[0];
    expect(queryCall?.[0]).toContain('FROM audit_log_events');
    expect(queryCall?.[1]?.at(-1)).toBe(3);
  });

  it('applies filters and cursor parameters to the query', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });

    const cursor = encodeCursor('2024-06-25T00:00:00.000Z', 'event-prev');

    if (!app) {
      throw new Error('server not initialised');
    }

    const response = await app.inject({
      method: 'GET',
      url: '/v1/audit/events',
      headers: authHeaders,
      query: {
        project_id: '9a3f0f79-6d2f-4860-8d72-27fbe74952a0',
        event_type: 'scan.failed',
        actor: 'key-77',
        from: '2024-06-01T00:00:00.000Z',
        to: '2024-07-01T00:00:00.000Z',
        limit: 25,
        cursor
      }
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledTimes(1);

    const [text, values] = db.query.mock.calls[0] ?? [];
    expect(text).toContain('audit_log_events');
    expect(text).toContain('(e.created_at, e.id) <');
    expect(values).toEqual([
      TENANT_ID,
      '9a3f0f79-6d2f-4860-8d72-27fbe74952a0',
      'scan.failed',
      'key-77',
      '2024-06-01T00:00:00.000Z',
      '2024-07-01T00:00:00.000Z',
      '2024-06-25T00:00:00.000Z',
      'event-prev',
      26
    ]);
  });

  it('rejects invalid cursor values', async () => {
    if (!app) {
      throw new Error('server not initialised');
    }

    const response = await app.inject({
      method: 'GET',
      url: '/v1/audit/events',
      headers: authHeaders,
      query: { cursor: 'not-a-valid-cursor' }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('denies access when caller lacks auditor privileges', async () => {
    if (app) {
      await app.close();
    }

    const auth = createAuthMocks(TENANT_ID, ['Developer']);
    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: auth.lookupApiKey,
      licenseStatusProvider: createLicenseStatusProvider()
    });

    if (!app) {
      throw new Error('server not initialised');
    }

    const response = await app.inject({
      method: 'GET',
      url: '/v1/audit/events',
      headers: auth.headers
    });

    expect(response.statusCode).toBe(403);
    expect(db.query).not.toHaveBeenCalled();
  });

  it('streams ndjson when format=jsonl', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: 'event-jsonl-new',
          tenant_id: TENANT_ID,
          project_id: null,
          scan_id: null,
          actor_type: 'api_key',
          actor_identifier: 'key-1',
          event_type: 'policy.evaluated',
          event_payload: { policy: 'strict' },
          event_hash: 'hash-jsonl-new',
          created_at: '2024-07-03T09:00:00.000Z'
        },
        {
          id: 'event-jsonl-old',
          tenant_id: TENANT_ID,
          project_id: null,
          scan_id: null,
          actor_type: 'api_key',
          actor_identifier: 'key-1',
          event_type: 'policy.evaluated',
          event_payload: { policy: 'baseline' },
          event_hash: 'hash-jsonl-old',
          created_at: '2024-07-02T09:00:00.000Z'
        }
      ]
    });

    if (!app) {
      throw new Error('server not initialised');
    }

    const response = await app.inject({
      method: 'GET',
      url: '/v1/audit/events',
      headers: authHeaders,
      query: { format: 'jsonl', limit: 1 }
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('application/x-ndjson');
    expect(response.body?.trim()).toBe(
      JSON.stringify({
        id: 'event-jsonl-new',
        tenant_id: TENANT_ID,
        project_id: null,
        scan_id: null,
        actor_type: 'api_key',
        actor_identifier: 'key-1',
        event_type: 'policy.evaluated',
        event_payload: { policy: 'strict' },
        event_hash: 'hash-jsonl-new',
        created_at: '2024-07-03T09:00:00.000Z'
      })
    );
    expect(response.headers['x-next-cursor']).toBeDefined();
  });
});
