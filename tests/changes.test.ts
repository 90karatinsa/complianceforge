// SPDX-License-Identifier: MIT

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
    Counter: MockMetric,
    Gauge: MockMetric,
    Histogram: MockMetric,
    Registry: MockRegistry,
    collectDefaultMetrics: () => {}
  } satisfies Record<string, unknown>;
}, { virtual: true });

const TEST_VERSION = '0.0.0-test';
const TENANT_ID = 'tenant-456';
const SINCE = '2024-01-01T00:00:00.000Z';

describe('changes feed endpoint', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    db = {
      query: vi.fn()
    } as { query: ReturnType<typeof vi.fn> } & Database;

    queue = {
      add: vi.fn().mockResolvedValue(undefined)
    } as JobQueue;

    redis = {
      ping: vi.fn().mockResolvedValue('PONG')
    } satisfies RedisConnection;

    metrics = {
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

    const auth = createAuthMocks(TENANT_ID);
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
    await app.close();
    vi.restoreAllMocks();
  });

  it('lists scan events since the provided timestamp', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: 'scan-1',
          project_id: 'project-1',
          project_name: 'Demo',
          status: 'succeeded',
          policy_result: 'allowed',
          completed_at: '2024-01-03T12:00:00.000Z',
          created_at: '2024-01-03T10:00:00.000Z'
        },
        {
          id: 'scan-2',
          project_id: 'project-2',
          project_name: 'Demo 2',
          status: 'failed',
          policy_result: 'failed',
          completed_at: null,
          created_at: '2024-01-04T08:30:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/changes',
      headers: authHeaders,
      query: { since: SINCE }
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledTimes(1);
    const call = db.query.mock.calls[0];
    expect(call?.[0]).toContain("COALESCE(s.completed_at, s.created_at) >=");
    expect(call?.[1]).toEqual([TENANT_ID, SINCE]);

    expect(response.json()).toEqual({
      data: [
        {
          id: 'scan-1',
          scan_id: 'scan-1',
          project_id: 'project-1',
          project_name: 'Demo',
          status: 'succeeded',
          policy_result: 'pass',
          occurred_at: '2024-01-03T12:00:00.000Z',
          type: 'scan.completed',
          links: {
            scan: '/v1/scans/scan-1',
            sbom: '/v1/sboms/scan-1'
          }
        },
        {
          id: 'scan-2',
          scan_id: 'scan-2',
          project_id: 'project-2',
          project_name: 'Demo 2',
          status: 'failed',
          policy_result: 'fail',
          occurred_at: '2024-01-04T08:30:00.000Z',
          type: 'scan.failed',
          links: {
            scan: '/v1/scans/scan-2',
            sbom: '/v1/sboms/scan-2'
          }
        }
      ]
    });
  });

  it('validates the since parameter', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/changes',
      headers: authHeaders
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('applies status filters when type is provided', async () => {
    db.query.mockImplementationOnce((sql: string, values?: unknown[]) => {
      expect(sql).toContain("s.status = 'failed'");
      expect(values).toEqual([TENANT_ID, SINCE]);
      return Promise.resolve({ rows: [] });
    });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/changes',
      headers: authHeaders,
      query: { since: SINCE, type: 'scan.failed' }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ data: [] });
  });
});
