// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';
import * as crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.js';
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

    get contentType(): string {
      return 'text/plain';
    }
  }

  return {
    Registry: MockRegistry,
    Gauge: MockMetric,
    Counter: MockMetric,
    Histogram: MockMetric,
    collectDefaultMetrics: () => {
      // noop
    },
    registry: {
      metrics: () => Promise.resolve(''),
      contentType: 'text/plain'
    },
    queueDepthGauge: {
      set: () => {
        // noop for tests
      }
    },
    scanDurationHistogram: {
      startTimer: () => () => {
        // noop
      }
    },
    noticeBuildHistogram: {
      startTimer: () => () => {
        // noop
      }
    },
    webhookOutcomeCounter: {
      inc: () => {
        // noop
      }
    },
    feedImportCounter: {
      inc: () => {
        // noop
      }
    },
    vexStateGauge: {
      set: () => {
        // noop
      }
    },
    purgeDurationHistogram: {
      startTimer: () => () => {
        // noop
      }
    }
  } satisfies Metrics;
});

const TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WEBHOOK_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const TEST_VERSION = '0.0.0-test';

function createDbMock(): { query: ReturnType<typeof vi.fn> } & Database {
  return {
    query: vi.fn()
  } as { query: ReturnType<typeof vi.fn> } & Database;
}

function createQueueMock(): { add: ReturnType<typeof vi.fn> } & JobQueue {
  return {
    add: vi.fn().mockResolvedValue(undefined)
  } as { add: ReturnType<typeof vi.fn> } & JobQueue;
}

function createRedisMock(): RedisConnection {
  return { ping: vi.fn().mockResolvedValue('PONG') } satisfies RedisConnection;
}

function createMetricsStub(): Metrics {
  return {
    registry: { metrics: () => Promise.resolve(''), contentType: 'text/plain' },
    queueDepthGauge: { set: () => {} },
    scanDurationHistogram: { startTimer: () => () => {} },
    noticeBuildHistogram: { startTimer: () => () => {} },
    webhookOutcomeCounter: { inc: () => {} },
    feedImportCounter: { inc: () => {} },
    vexStateGauge: { set: () => {} },
    purgeDurationHistogram: { startTimer: () => () => {} }
  } satisfies Metrics;
}

describe('webhooks endpoint', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;
  let randomBytesSpy: ReturnType<typeof vi.spyOn> | null = null;

  beforeEach(async () => {
    db = createDbMock();
    db.query.mockResolvedValue({ rows: [] });
    queue = createQueueMock();
    redis = createRedisMock();
    metrics = createMetricsStub();
    const auth = createAuthMocks(TENANT_ID);
    authHeaders = auth.headers;
    randomBytesSpy = vi.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.alloc(12, 0x01));
    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      generateId: () => WEBHOOK_ID,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: auth.lookupApiKey,
      licenseStatusProvider: createLicenseStatusProvider()
    });
  });

  afterEach(async () => {
    await app.close();
    vi.restoreAllMocks();
    randomBytesSpy?.mockRestore();
    randomBytesSpy = null;
  });

  it('registers a webhook subscription', async () => {
    const payload = {
      tenant_id: TENANT_ID,
      url: 'https://hooks.example.com/notify',
      secret: 'supersecretvalue',
      events: ['scan.completed', 'scan.failed']
    };

    const secretKey = Buffer.alloc(32, 0x42);
    const iv = Buffer.alloc(12, 0x01);
    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv, { authTagLength: 16 });
    const ciphertext = Buffer.concat([cipher.update(payload.secret, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const createdWebhook = {
      id: WEBHOOK_ID,
      tenant_id: TENANT_ID,
      url: payload.url,
      secret_ciphertext: ciphertext,
      secret_iv: iv,
      secret_auth_tag: authTag,
      secret_last_four: 'alue',
      events: payload.events,
      created_at: '2024-01-07T00:00:00.000Z',
      updated_at: '2024-01-07T00:00:00.000Z'
    } satisfies Record<string, unknown>;

    db.query.mockResolvedValueOnce({ rows: [createdWebhook] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/webhooks',
      headers: authHeaders,
      payload
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      data: {
        id: WEBHOOK_ID,
        tenant_id: TENANT_ID,
        url: payload.url,
        events: payload.events,
        created_at: '2024-01-07T00:00:00.000Z',
        updated_at: '2024-01-07T00:00:00.000Z',
        secret: { has_secret: true, last_four: 'alue', masked: '••••alue' },
        delivery: { last_success_at: null, last_failure_at: null, failure_count: 0 }
      }
    });
    const queryCalls = db.query.mock.calls as Array<Parameters<Database['query']>>;
    const [, values] = queryCalls[0] ?? [];
    expect(values).toEqual([
      WEBHOOK_ID,
      TENANT_ID,
      payload.url,
      ciphertext,
      iv,
      authTag,
      'alue',
      payload.events
    ]);
    const auditCall = queryCalls.find(([text]) => typeof text === 'string' && text.includes('INSERT INTO audit_log_events'));
    expect(auditCall).toBeDefined();
  });

  it('rejects duplicate webhook URLs for a tenant', async () => {
    db.query.mockRejectedValueOnce({ code: '23505' });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/webhooks',
      headers: authHeaders,
      payload: {
        tenant_id: TENANT_ID,
        url: 'https://hooks.example.com/notify',
        secret: 'anothersecret',
        events: ['scan.completed']
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });
  });

  it('validates webhook payloads', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/webhooks',
      headers: authHeaders,
      payload: {
        tenant_id: 'not-a-uuid',
        url: 'invalid-url',
        events: []
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });
  });

  it('lists webhooks with pagination and masked secret metadata', async () => {
    const rows = [
      {
        id: 'hook-1',
        tenant_id: TENANT_ID,
        url: 'https://hooks.example.com/notify',
        secret_last_four: 'abcd',
        events: ['scan.completed'],
        created_at: '2024-01-07T00:00:00.000Z',
        updated_at: '2024-01-08T00:00:00.000Z'
      }
    ];

    db.query.mockResolvedValueOnce({ rows });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/webhooks?tenant_id=${TENANT_ID}&page=1&page_size=5`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: [
        {
          id: 'hook-1',
          tenant_id: TENANT_ID,
          url: 'https://hooks.example.com/notify',
          events: ['scan.completed'],
          created_at: '2024-01-07T00:00:00.000Z',
          updated_at: '2024-01-08T00:00:00.000Z',
          secret: { has_secret: true, last_four: 'abcd', masked: '••••abcd' },
          delivery: { last_success_at: null, last_failure_at: null, failure_count: 0 }
        }
      ],
      pagination: { page: 1, page_size: 5, count: 1 }
    });

    const queryCalls = db.query.mock.calls as Array<Parameters<Database['query']>>;
    const listCall = queryCalls.find(([text]) => typeof text === 'string' && text.includes('FROM webhooks'));
    expect(listCall?.[0]).toContain('ORDER BY created_at DESC');
    const auditCall = queryCalls.find(([text]) => typeof text === 'string' && text.includes('INSERT INTO audit_log_events'));
    expect(auditCall).toBeDefined();
  });

  it('filters webhooks by subscribed event', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/webhooks?tenant_id=${TENANT_ID}&page=2&page_size=10&event=scan.failed`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: [],
      pagination: { page: 2, page_size: 10, count: 0 }
    });

    const listCall = db.query.mock.calls.find(([text]) => typeof text === 'string' && text.includes('FROM webhooks'));
    expect(listCall?.[0]).toContain('ANY(events)');
  });

  it('rejects webhook registrations that do not use HTTPS', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/webhooks',
      headers: authHeaders,
      payload: {
        tenant_id: TENANT_ID,
        url: 'http://hooks.example.com/insecure',
        secret: 'supersecretvalue',
        events: ['scan.completed']
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Webhook URL must use HTTPS.'
      }
    });
  });
});
