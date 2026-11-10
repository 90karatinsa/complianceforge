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

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: class {
    send = vi.fn();
  },
  GetSecretValueCommand: class {}
}));

const TEST_TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const TEST_PROJECT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function createQueueMock(): { add: ReturnType<typeof vi.fn> } & JobQueue {
  const add = vi.fn().mockResolvedValue(undefined);
  return { add } as { add: ReturnType<typeof vi.fn> } & JobQueue;
}

function createRedisMock(): RedisConnection {
  return { ping: vi.fn().mockResolvedValue('PONG') } satisfies RedisConnection;
}

describe('artifact gate integration API', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    const auth = createAuthMocks(TEST_TENANT_ID, ['Security']);
    authHeaders = auth.headers;
    queue = createQueueMock();
    redis = createRedisMock();
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

    db = {
      query: vi.fn()
    } as { query: ReturnType<typeof vi.fn> } & Database;

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

  it('approves uploads when the latest scan passes', async () => {
    db.query.mockImplementation((text: string) => {
      if (text.includes('FROM scans')) {
        return Promise.resolve({
          rows: [
            {
              id: 'scan-pass',
              policy_result: 'pass',
              completed_at: '2024-01-01T00:00:00.000Z',
              findings: { policy: { reasons: ['threshold_ok'] } }
            }
          ]
        });
      }

      if (text.startsWith('INSERT INTO audit_log_events')) {
        return Promise.resolve({ rows: [] });
      }

      return Promise.resolve({ rows: [] });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/integrations/artifact-gate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        artifact_name: 'registry.example.com/app:1.0.0',
        requested_by: 'ci-bot'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      decision: 'allow',
      policy_result: 'pass',
      scan_id: 'scan-pass',
      policy_reasons: ['threshold_ok']
    });

    const auditCall = db.query.mock.calls.find(([text]) => typeof text === 'string' && text.includes('INSERT INTO audit_log_events'));
    expect(auditCall?.[1]?.[5]).toBe('integration.artifact_gate');
    const auditPayload = auditCall?.[1]?.[6] as { decision?: string } | undefined;
    expect(auditPayload).toMatchObject({ decision: 'allow', policy_result: 'pass' });
  });

  it('denies uploads when no successful scan exists', async () => {
    db.query.mockImplementation((text: string) => {
      if (text.includes('FROM scans')) {
        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('INSERT INTO audit_log_events')) {
        return Promise.resolve({ rows: [] });
      }

      return Promise.resolve({ rows: [] });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/integrations/artifact-gate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        artifact_name: 'registry.example.com/app:1.0.0'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      decision: 'deny',
      reason: 'no_successful_scan',
      policy_result: null,
      policy_reasons: []
    });

    const auditCall = db.query.mock.calls.find(([text]) => typeof text === 'string' && text.includes('INSERT INTO audit_log_events'));
    expect(auditCall?.[1]?.[5]).toBe('integration.artifact_gate');
    const payload = auditCall?.[1]?.[6] as { reason?: string } | undefined;
    expect(payload?.reason).toBe('no_successful_scan');
  });
});
