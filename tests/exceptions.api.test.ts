// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: class {
    public send = vi.fn(() => Promise.resolve({}));
  },
  GetSecretValueCommand: class {
    public readonly input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  }
}));

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
    Counter: MockMetric,
    Gauge: MockMetric,
    Histogram: MockMetric,
    Registry: MockRegistry,
    collectDefaultMetrics: () => {}
  } satisfies Record<string, unknown>;
});

const TEST_TENANT_ID = '99999999-9999-4999-8999-999999999999';
const TEST_EXCEPTION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function createDbMock(): { query: ReturnType<typeof vi.fn> } & Database {
  const query = vi.fn();
  return { query } as { query: ReturnType<typeof vi.fn> } & Database;
}

function createQueueMock(): { add: ReturnType<typeof vi.fn> } & JobQueue {
  const add = vi.fn().mockResolvedValue(undefined);
  return { add } as { add: ReturnType<typeof vi.fn> } & JobQueue;
}

function createRedisMock(): RedisConnection {
  return {
    ping: vi.fn().mockResolvedValue('PONG')
  } satisfies RedisConnection;
}

describe('policy exceptions endpoints', () => {
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
    const auth = createAuthMocks(TEST_TENANT_ID, ['Security']);
    authHeaders = auth.headers;

    metrics = {
      registry: { metrics: () => Promise.resolve(''), contentType: 'text/plain' },
      queueDepthGauge: { set: () => {} },
      scanDurationHistogram: { startTimer: () => () => {} },
      noticeBuildHistogram: { startTimer: () => () => {} },
      webhookOutcomeCounter: { inc: () => {} },
      feedImportCounter: { inc: () => {} },
      vexStateGauge: { set: () => {} },
      purgeDurationHistogram: { startTimer: () => () => {} }
    } satisfies Metrics;

    app = await buildServer({
      version: '0.0.0-test',
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
    await app.close();
    vi.restoreAllMocks();
  });

  it('lists exceptions for a tenant', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: TEST_EXCEPTION_ID,
          tenant_id: TEST_TENANT_ID,
          project_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          component_purl: 'pkg:npm/example@1.0.0',
          scope: 'package',
          status: 'pending',
          rationale: 'Temporary allowance',
          requested_by: 'alice',
          approved_by: null,
          approval_notes: null,
          requested_at: '2024-01-01T00:00:00.000Z',
          approved_at: null,
          expires_at: null,
          metadata: {}
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/exceptions?tenant_id=${TEST_TENANT_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('FROM policy_exceptions'), [
      TEST_TENANT_ID,
      null,
      null
    ]);
  });

  it('creates a pending exception and records an audit event', async () => {
    db.query
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_EXCEPTION_ID,
            tenant_id: TEST_TENANT_ID,
            project_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            component_purl: 'pkg:npm/example@1.0.0',
            scope: 'package',
            status: 'pending',
            rationale: 'Temporary allowance',
            requested_by: 'alice',
            approved_by: null,
            approval_notes: null,
            requested_at: '2024-01-01T00:00:00.000Z',
            approved_at: null,
            expires_at: null,
            metadata: {}
          }
        ]
      })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/exceptions',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        component_purl: 'pkg:npm/example@1.0.0',
        scope: 'package',
        rationale: 'Temporary allowance',
        requested_by: 'alice'
      }
    });

    expect(response.statusCode).toBe(201);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO policy_exceptions'), expect.any(Array));
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO audit_log_events'), expect.any(Array));
  });

  it('updates an exception status to approved', async () => {
    db.query
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_EXCEPTION_ID,
            tenant_id: TEST_TENANT_ID,
            project_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            component_purl: 'pkg:npm/example@1.0.0',
            scope: 'package',
            status: 'approved',
            rationale: 'Temporary allowance',
            requested_by: 'alice',
            approved_by: 'api-key-1',
            approval_notes: 'granted',
            requested_at: '2024-01-01T00:00:00.000Z',
            approved_at: '2024-01-02T00:00:00.000Z',
            expires_at: '2024-02-01T00:00:00.000Z',
            metadata: {}
          }
        ]
      })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'PUT',
      url: `/v1/exceptions/${TEST_EXCEPTION_ID}`,
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        status: 'approved',
        approval_notes: 'granted',
        expires_at: '2024-02-01T00:00:00.000Z'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('UPDATE policy_exceptions'), expect.any(Array));
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO audit_log_events'), expect.any(Array));
  });
});
