// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
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

const TEST_TENANT_ID = '77777777-7777-4777-8777-777777777777';
const TEST_VEX_ID = '88888888-8888-4888-8888-888888888888';

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

describe('VEX endpoints', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let gaugeSet: ReturnType<typeof vi.fn>;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisMock();
    gaugeSet = vi.fn();
    const auth = createAuthMocks(TEST_TENANT_ID, ['Security']);
    authHeaders = auth.headers;

    metrics = {
      registry: { metrics: () => Promise.resolve(''), contentType: 'text/plain' },
      queueDepthGauge: { set: () => {} },
      scanDurationHistogram: { startTimer: () => () => {} },
      noticeBuildHistogram: { startTimer: () => () => {} },
      webhookOutcomeCounter: { inc: () => {} },
      feedImportCounter: { inc: () => {} },
      vexStateGauge: { set: gaugeSet },
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

  it('lists VEX statements by tenant', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: TEST_VEX_ID,
          component_purl: 'pkg:npm/example@1.0.0',
          advisory_id: 'CVE-1234',
          status: 'not_affected',
          justification: 'not exploitable',
          metadata: {},
          issued_at: '2024-01-01T00:00:00.000Z',
          updated_at: '2024-01-02T00:00:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/vex?tenant_id=${TEST_TENANT_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('FROM vex_statements'), [
      TEST_TENANT_ID,
      null
    ]);
  });

  it('creates a VEX statement and updates metrics', async () => {
    db.query
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_VEX_ID,
            tenant_id: TEST_TENANT_ID,
            component_purl: 'pkg:npm/example@1.0.0',
            advisory_id: 'CVE-1234',
            status: 'not_affected',
            justification: 'not exploitable',
            metadata: {},
            issued_at: '2024-01-01T00:00:00.000Z',
            updated_at: '2024-01-01T00:00:00.000Z'
          }
        ]
      })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/vex',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        component_purl: 'pkg:npm/example@1.0.0',
        advisory_id: 'CVE-1234',
        status: 'not_affected'
      }
    });

    expect(response.statusCode).toBe(201);
    expect(gaugeSet).toHaveBeenCalledWith('not_affected', 1);
  });

  it('updates a VEX statement', async () => {
    db.query
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_VEX_ID,
            tenant_id: TEST_TENANT_ID,
            component_purl: 'pkg:npm/example@1.0.0',
            advisory_id: 'CVE-1234',
            status: 'fixed',
            justification: 'Patched',
            metadata: {},
            issued_at: '2024-01-01T00:00:00.000Z',
            updated_at: '2024-01-02T00:00:00.000Z'
          }
        ]
      })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'PUT',
      url: `/v1/vex/${TEST_VEX_ID}`,
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        status: 'fixed',
        justification: 'Patched'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(gaugeSet).toHaveBeenCalledWith('fixed', 1);
  });

  it('deletes a VEX statement and resets the gauge', async () => {
    db.query
      .mockResolvedValueOnce({ rows: [{ status: 'not_affected' }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'DELETE',
      url: `/v1/vex/${TEST_VEX_ID}`,
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID
      }
    });

    expect(response.statusCode).toBe(204);
    expect(gaugeSet).toHaveBeenCalledWith('not_affected', 0);
  });
});
