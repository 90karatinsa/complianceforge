// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';
import { createHash } from 'node:crypto';
import argon2 from 'argon2';

const TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const TEST_VERSION = '0.0.0-test';
const API_KEY_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function createDbMock(): { query: ReturnType<typeof vi.fn> } & Database {
  return {
    query: vi.fn().mockResolvedValue({ rows: [] })
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

describe('API key management endpoints', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisMock();
    metrics = createMetricsStub();
    const auth = createAuthMocks(TENANT_ID);
    authHeaders = auth.headers;

    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      generateId: () => API_KEY_ID,
      lookupApiKey: auth.lookupApiKey,
      licenseStatusProvider: createLicenseStatusProvider()
    });

    await app.ready();
  });

  afterEach(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it('creates a new API key and returns the plaintext token once', async () => {
    const createdAt = '2024-07-10T10:00:00.000Z';
    db.query.mockImplementationOnce(async (sql: unknown) => {
      if (typeof sql === 'string' && sql.startsWith('INSERT INTO api_keys')) {
        return { rows: [{ id: API_KEY_ID, created_at: createdAt }] };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/api-keys',
      headers: authHeaders,
      payload: {
        tenant_id: TENANT_ID,
        name: 'CI Gateway',
        roles: ['Admin', 'Security']
      }
    });

    expect(response.statusCode).toBe(201);
    const body = response.json<{ data: { plaintext_token: string; id: string; last_four: string } }>();
    expect(body.data.id).toBe(API_KEY_ID);
    expect(body.data.plaintext_token).toMatch(/^aka_[0-9a-f]{32}$/);
    expect(body.data.last_four).toHaveLength(4);

    const insertCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.startsWith('INSERT INTO api_keys')
    );

    expect(insertCall).toBeDefined();
    if (!insertCall) {
      throw new Error('Expected insert call to be defined');
    }

    const [, values] = insertCall as [string, unknown[]];
    expect(values?.[0]).toBe(TENANT_ID);
    expect(values?.[1]).toBe('CI Gateway');
    expect(typeof values?.[2]).toBe('string');
    expect(typeof values?.[3]).toBe('string');
    expect(values?.[2]).toMatch(/^\$argon2id\$/);

    const lookupHash = values?.[3];
    if (typeof lookupHash !== 'string') {
      throw new Error('Lookup hash missing');
    }

    const expectedLookup = createHash('sha256')
      .update(`${TEST_API_KEY_SALT}:${body.data.plaintext_token}`)
      .digest('hex');
    expect(lookupHash).toBe(expectedLookup);
    await expect(argon2.verify(values?.[2] as string, lookupHash)).resolves.toBe(true);
  });

  it('lists API keys with masked tokens and pagination metadata', async () => {
    const createdAt = '2024-07-11T12:00:00.000Z';
    db.query.mockImplementation(async (sql: unknown, params?: unknown[]) => {
      if (typeof sql === 'string' && sql.startsWith('SELECT id, name, permissions')) {
        return {
          rows: [
            {
              id: API_KEY_ID,
              name: 'Service Token',
              permissions: ['Admin'],
              created_at: createdAt,
              last_used_at: null,
              token_lookup_hash: 'abcdef1234567890'
            }
          ]
        };
      }

      if (typeof sql === 'string' && sql.includes('COUNT(*)')) {
        expect(params).toEqual([TENANT_ID]);
        return { rows: [{ count: '1' }] };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/api-keys?tenant_id=${TENANT_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json<{
      data: Array<{ id: string; masked_token: string; last_four: string; roles: string[] }>;
      pagination: { count: number; page: number; page_size: number };
    }>();

    expect(payload.pagination).toEqual({ page: 1, page_size: 20, count: 1 });
    expect(payload.data).toHaveLength(1);
    expect(payload.data[0]).toMatchObject({
      id: API_KEY_ID,
      masked_token: '•••• 7890',
      last_four: '7890',
      roles: ['Admin']
    });
  });

  it('revokes an API key', async () => {
    db.query.mockImplementation(async (sql: unknown) => {
      if (typeof sql === 'string' && sql.startsWith('DELETE FROM api_keys')) {
        return {
          rows: [
            {
              id: API_KEY_ID,
              tenant_id: TENANT_ID,
              name: 'Legacy Token',
              permissions: ['Admin'],
              token_hash: 'legacy'
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'DELETE',
      url: `/v1/api-keys/${API_KEY_ID}`,
      headers: authHeaders,
      payload: { tenant_id: TENANT_ID }
    });

    expect(response.statusCode).toBe(204);
  });

  it('rejects API key management for non-admin roles', async () => {
    const auth = createAuthMocks(TENANT_ID, ['Developer']);
    const altApp = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: auth.lookupApiKey,
      licenseStatusProvider: createLicenseStatusProvider()
    });

    await altApp.ready();

    const response = await altApp.inject({
      method: 'GET',
      url: `/v1/api-keys?tenant_id=${TENANT_ID}`,
      headers: auth.headers
    });

    expect(response.statusCode).toBe(403);
    await altApp.close();
  });
});
