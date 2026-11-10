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

const TEST_TENANT_ID = '12345678-1234-4234-8234-123456789abc';

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

describe('RBAC and SSO', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;

  afterEach(async () => {
    if (app) {
      await app.close();
    }

    vi.restoreAllMocks();
  });

  it('rejects access when role is insufficient', async () => {
    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisMock();
    metrics = createMetricsStub();
    const auth = createAuthMocks(TEST_TENANT_ID, ['Developer']);

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

    const response = await app.inject({
      method: 'GET',
      url: `/v1/legal/findings?tenant_id=${TEST_TENANT_ID}`,
      headers: auth.headers
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      error: { code: 'forbidden' }
    });
  });

  it('allows SSO handlers to authenticate and records an audit event', async () => {
    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisMock();
    metrics = createMetricsStub();

    const ssoHandler = vi.fn().mockResolvedValue({
      tenantId: TEST_TENANT_ID,
      apiKeyId: 'api-key',
      roles: ['Developer'],
      subject: 'user@example.com'
    });

    app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: vi.fn().mockResolvedValue(null),
      ssoHandlers: { saml: ssoHandler },
      licenseStatusProvider: createLicenseStatusProvider()
    });

    db.query.mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/auth/sso/saml',
      payload: { assertion: 'ticket' }
    });

    expect(response.statusCode).toBe(200);
    expect(ssoHandler).toHaveBeenCalled();
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO audit_log_events'), expect.any(Array));
  });
});
