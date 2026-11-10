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

const TEST_TENANT_ID = '11111111-1111-4111-8111-111111111111';

describe('health route', () => {
  let originalNodeEnv: string | undefined;
  let db: Database;
  let queue: JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let queueDepthGaugeMock: ReturnType<typeof vi.fn>;
  let lookupApiKey: ReturnType<typeof createAuthMocks>['lookupApiKey'];
  let licenseStatusProvider: ReturnType<typeof createLicenseStatusProvider>;

  beforeEach(() => {
    originalNodeEnv = process.env.NODE_ENV;
    const dbQuery = vi.fn((text: string) => {
      if (text.includes('MAX(')) {
        return Promise.resolve({ rows: [{ last_scan_at: new Date('2024-01-01T00:00:00.000Z') }] });
      }

      if (text.includes('FROM tenants') && text.includes('feed_manifests')) {
        return Promise.resolve({
          rows: [
            {
              active_version: 'feed-2024.07',
              resolved_active_version: 'feed-2024.07',
              active_imported_at: new Date('2024-07-01T10:00:00.000Z'),
              active_verified_at: new Date('2024-07-01T10:05:00.000Z'),
              active_signature: 'signature-data',
              latest_version: 'feed-2024.07',
              latest_imported_at: new Date('2024-07-01T10:00:00.000Z'),
              latest_verified_at: new Date('2024-07-01T10:05:00.000Z'),
              latest_signature: 'signature-data'
            }
          ]
        });
      }

      if (text.includes('health_slo_metrics')) {
        return Promise.resolve({
          rows: [
            {
              summary_p95_ms: 310,
              orchestration_p95_ms: 720,
              worker_capacity: 12
            }
          ]
        });
      }

      if (text.includes('system_failures')) {
        return Promise.resolve({
          rows: [
            {
              occurred_at: new Date('2024-06-30T08:00:00.000Z'),
              message: 'Queue timeout'
            }
          ]
        });
      }

      if (text.includes('vex_statements')) {
        return Promise.resolve({ rows: [{ total: 5 }] });
      }

      return Promise.resolve({ rows: [] });
    });

    db = { query: dbQuery };

    queue = {
      add: vi.fn().mockResolvedValue(undefined),
      getJobCounts: vi.fn().mockResolvedValue({ waiting: 5, active: 2, delayed: 1 })
    } satisfies JobQueue;

    redis = {
      ping: vi.fn().mockResolvedValue('PONG')
    } satisfies RedisConnection;

    queueDepthGaugeMock = vi.fn();
    metrics = {
      registry: {
        metrics: vi.fn(() =>
          Promise.resolve(`# HELP otomatik_scan_queue_depth\n# TYPE otomatik_scan_queue_depth gauge\notomatik_scan_queue_depth{state=\"waiting\"} 5`)
        ),
        contentType: 'text/plain'
      },
      queueDepthGauge: {
        set: queueDepthGaugeMock
      },
      scanDurationHistogram: {
        startTimer: () => () => {
          // unused in these tests
        }
      },
      noticeBuildHistogram: {
        startTimer: () => () => {
          // unused
        }
      },
      webhookOutcomeCounter: {
        inc: () => {
          // unused in these tests
        }
      },
      feedImportCounter: {
        inc: () => {
          // unused
        }
      },
      vexStateGauge: {
        set: () => {
          // unused
        }
      },
      purgeDurationHistogram: {
        startTimer: () => () => {
          // unused
        }
      }
    } satisfies Metrics;
    const auth = createAuthMocks(TEST_TENANT_ID);
    lookupApiKey = auth.lookupApiKey;
    licenseStatusProvider = createLicenseStatusProvider();
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }

    process.env.NODE_ENV = originalNodeEnv;
    vi.restoreAllMocks();
  });

  it('reports dependency status and exposes metrics', async () => {
    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider
    });

    const response = await app.inject({ method: 'GET', url: '/v1/health' });
    expect(response.statusCode).toBe(200);
    const payload = response.json<{
      status: string;
      dependencies: Record<string, string>;
      queue: { waiting: number; active: number; delayed: number };
      last_scan_at: string | null;
      feeds: { active_version: string | null; last_imported_at: string | null; signature_status: string | null };
      vex: { total: number };
      worker_capacity: number | null;
      slo: { summary_p95_ms: number; orchestration_p95_ms: number };
      last_failures: Array<{ occurred_at: string; message: string }>;
      details: { summary: string };
    }>();
    expect(payload.status).toBe('healthy');
    expect(payload.dependencies).toEqual({ db: 'ok', redis: 'ok', bull: 'ok' });
    expect(payload.queue).toEqual({ waiting: 5, active: 2, delayed: 1 });
    expect(payload.last_scan_at).toBe('2024-01-01T00:00:00.000Z');
    expect(payload.feeds.active_version).toBe('feed-2024.07');
    expect(payload.feeds.last_imported_at).toBe('2024-07-01T10:00:00.000Z');
    expect(payload.feeds.signature_status).toBe('İmza doğrulandı');
    expect(payload.vex.total).toBe(5);
    expect(payload.worker_capacity).toBe(12);
    expect(payload.slo.summary_p95_ms).toBe(310);
    expect(payload.slo.orchestration_p95_ms).toBe(720);
    expect(payload.last_failures).toEqual([
      {
        occurred_at: '2024-06-30T08:00:00.000Z',
        message: 'Queue timeout'
      }
    ]);
    expect(payload.details.summary).toContain('sağlıklı');

    expect(queueDepthGaugeMock).toHaveBeenNthCalledWith(1, 'waiting', 5);
    expect(queueDepthGaugeMock).toHaveBeenNthCalledWith(2, 'active', 2);
    expect(queueDepthGaugeMock).toHaveBeenNthCalledWith(3, 'delayed', 1);

    const metricsResponse = await app.inject({ method: 'GET', url: '/metrics' });
    expect(metricsResponse.statusCode).toBe(200);
    expect(metricsResponse.headers['content-type']).toBe('text/plain');
    expect(metricsResponse.body).toContain('otomatik_scan_queue_depth');

    const queryMock = db.query as ReturnType<typeof vi.fn>;
    const executedSql = queryMock.mock.calls.map(([sql]) => sql);
    expect(executedSql).toEqual(
      expect.arrayContaining([
        expect.stringContaining('SELECT MAX(completed_at) AS last_scan_at FROM scans'),
        expect.stringContaining("metadata->>'active_feed_version'"),
        expect.stringContaining('SELECT COUNT(*)::int AS total FROM vex_statements'),
        expect.stringContaining('SELECT summary_p95_ms, orchestration_p95_ms, worker_capacity FROM health_slo_metrics'),
        expect.stringContaining('SELECT occurred_at, message FROM system_failures')
      ])
    );
  });

  it('returns 503 when queue metrics cannot be retrieved', async () => {
    queue = {
      ...queue,
      getJobCounts: vi.fn(() => Promise.reject(new Error('redis down')))
    } satisfies JobQueue;

    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider
    });

    const response = await app.inject({ method: 'GET', url: '/v1/health' });
    expect(response.statusCode).toBe(503);
    const payload = response.json<{
      status: string;
      dependencies: Record<string, string>;
      queue: { waiting: number };
      details: { summary: string };
    }>();
    expect(payload.status).toBe('degraded');
    expect(payload.dependencies.bull).toBe('error');
    expect(payload.queue.waiting).toBe(0);
    expect(payload.details.summary).toContain('Kuyruk');

    expect(queueDepthGaugeMock).toHaveBeenNthCalledWith(1, 'waiting', 0);
    expect(queueDepthGaugeMock).toHaveBeenNthCalledWith(2, 'active', 0);
    expect(queueDepthGaugeMock).toHaveBeenNthCalledWith(3, 'delayed', 0);
  });
  it('serves the health panel without authentication', async () => {
    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider
    });

    const response = await app.inject({ method: 'GET', url: '/health/panel' });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.body).toContain('Health Paneli');
  });

  it('caches the health panel html outside development mode', async () => {
    process.env.NODE_ENV = 'test';
    const loadHealthPanelHtml = vi.fn().mockResolvedValue('<html>CACHED</html>');

    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider,
      loadHealthPanelHtml
    });

    const first = await app.inject({ method: 'GET', url: '/health/panel' });
    const second = await app.inject({ method: 'GET', url: '/health/panel' });

    expect(loadHealthPanelHtml).toHaveBeenCalledTimes(1);
    expect(first.body).toContain('CACHED');
    expect(second.body).toContain('CACHED');
  });

  it('disables health panel caching in development mode', async () => {
    process.env.NODE_ENV = 'development';
    const loadHealthPanelHtml = vi.fn().mockResolvedValue('<html>DEV</html>');

    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider,
      loadHealthPanelHtml
    });

    await app.inject({ method: 'GET', url: '/health/panel' });
    await app.inject({ method: 'GET', url: '/health/panel' });

    expect(loadHealthPanelHtml).toHaveBeenCalledTimes(2);
  });

  it('returns down status when the database is unavailable', async () => {
    db = {
      query: vi.fn(() => Promise.reject(new Error('connection refused')))
    } as Database;

    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider
    });

    const response = await app.inject({ method: 'GET', url: '/v1/health' });
    expect(response.statusCode).toBe(503);
    const payload = response.json<{
      status: string;
      dependencies: Record<string, string>;
      details: { summary: string };
    }>();
    expect(payload.status).toBe('down');
    expect(payload.dependencies.db).toBe('error');
    expect(payload.details.summary).toContain('Veritabanı');
  });
});
