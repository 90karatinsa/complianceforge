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
const TENANT_ID = 'tenant-123';
const PROJECT_ID = '11111111-1111-4111-8111-111111111111';

describe('reports summary endpoint', () => {
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

  it('aggregates scan and vulnerability metrics', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          total_scans: 3,
          policy_pass: 1,
          policy_warn: 1,
          policy_fail: 1,
          license_violations: 3,
          average_duration_ms: 1000,
          vuln_critical: 1,
          vuln_high: 2,
          vuln_medium: 3,
          vuln_low: 0,
          vex_total: 4,
          vex_downgraded: 1
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/reports/summary',
      headers: authHeaders,
      query: {
        project_id: PROJECT_ID,
        from: '2024-01-01T00:00:00.000Z',
        to: '2024-01-31T23:59:59.000Z'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledTimes(1);
    const firstCall = db.query.mock.calls[0];
    expect(firstCall?.[0]).toContain('WITH filtered_scans');
    expect(firstCall?.[1]).toEqual([
      TENANT_ID,
      PROJECT_ID,
      '2024-01-01T00:00:00.000Z',
      '2024-01-31T23:59:59.000Z'
    ]);

    expect(response.json()).toEqual({
      data: {
        total_scans: 3,
        policy: {
          pass: 1,
          warn: 1,
          fail: 1
        },
        license_violations: 3,
        average_duration_ms: 1000,
        vulnerabilities: {
          critical: 1,
          high: 2,
          medium: 3,
          low: 0
        },
        vex_noise_reduction: {
          total: 4,
          downgraded: 1,
          ratio: 0.25
        }
      }
    });
  });

  it('validates query parameters', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/reports/summary',
      headers: authHeaders,
      query: { project_id: 'not-a-uuid' }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('exports CSV summaries and records audit events', async () => {
    const auditInserts: unknown[][] = [];

    db.query.mockImplementation(async (text, values) => {
      if (typeof text === 'string' && text.includes('WITH filtered_scans')) {
        return {
          rows: [
            {
              total_scans: 4,
              policy_pass: 2,
              policy_warn: 1,
              policy_fail: 1,
              license_violations: 5,
              average_duration_ms: 900,
              vuln_critical: 1,
              vuln_high: 2,
              vuln_medium: 3,
              vuln_low: 4,
              vex_total: 6,
              vex_downgraded: 3
            }
          ]
        };
      }

      if (typeof text === 'string' && text.includes('INSERT INTO audit_log_events')) {
        auditInserts.push(values ?? []);
        return { rows: [] };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/reports/export',
      headers: authHeaders,
      query: {
        project_id: PROJECT_ID,
        from: '2024-01-01T00:00:00.000Z',
        to: '2024-01-31T23:59:59.000Z'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/csv');
    expect(response.headers['content-disposition']).toContain(`project-${PROJECT_ID}`);
    expect(response.body).toContain('total_scans');
    expect(response.body).toContain('policy_pass');

    expect(auditInserts).toHaveLength(1);
    const values = auditInserts[0];
    expect(values[0]).toBe(TENANT_ID);
    expect(values[1]).toBe(PROJECT_ID);
    expect(values[5]).toBe('reports.exported');
    const payload = values[6] as Record<string, unknown>;
    expect(payload).toMatchObject({ project_id: PROJECT_ID });
    expect(typeof values[7]).toBe('string');
  });
});
