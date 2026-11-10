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
});

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(() => ({
    send: vi.fn(async () => ({ SecretString: '{}' }))
  })),
  GetSecretValueCommand: vi.fn()
}));

const TEST_TENANT_ID = '11111111-1111-4111-8111-111111111111';
const TEST_PROJECT_ID = '22222222-2222-4222-8222-222222222222';
const TEST_POLICY_ID = '33333333-3333-4333-8333-333333333333';

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
    purgeDurationHistogram: { startTimer: () => () => {} },
    vexNoiseGauge: { set: () => {} },
    vexDowngradedCounter: { inc: () => {} }
  } satisfies Metrics;
}

describe('SBOM import API', () => {
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

    const auth = createAuthMocks(TEST_TENANT_ID, ['Admin']);
    authHeaders = auth.headers;

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

  it('imports a CycloneDX SBOM and stores findings', async () => {
    db.query.mockImplementation(async (text: string) => {
      if (text.includes('FROM projects')) {
        return {
          rows: [
            {
              id: TEST_PROJECT_ID,
              tenant_id: TEST_TENANT_ID,
              name: 'Example',
              description: null,
              repo_url: null,
              oci_ref: null,
              metadata: {}
            }
          ]
        };
      }

      if (text.includes('FROM policies')) {
        return {
          rows: [
            {
              rules: {
                denied_spdx: ['GPL-3.0-ONLY']
              }
            }
          ]
        };
      }

      if (text.startsWith('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2024.01' } }] };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/sboms/import',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        policy_id: TEST_POLICY_ID,
        format: 'CycloneDX',
        sbom: {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          components: [
            {
              bomRef: 'pkg:npm/left-pad@1.0.0',
              name: 'left-pad',
              version: '1.0.0',
              purl: 'pkg:npm/left-pad@1.0.0',
              licenses: [{ license: { id: 'GPL-3.0-ONLY' } }]
            }
          ]
        }
      }
    });

    expect(response.statusCode).toBe(201);
    const body = response.json<{ data: { policy_result: string; findings: Record<string, unknown> } }>();
    expect(body.data.policy_result).toBe('fail');
    expect(body.data.findings).toMatchObject({
      packages: 1,
      licenses: 1,
      vulnerabilities: 0,
      policy: { result: 'fail' },
      vex: { downgraded: 0, total: 0 }
    });

    const calls = db.query.mock.calls as Array<Parameters<Database['query']>>;
    expect(calls.some(([sql]) => sql.includes('INSERT INTO sboms'))).toBe(true);
    expect(calls.some(([sql]) => sql.includes('INSERT INTO licenses'))).toBe(true);
    expect(calls.some(([sql]) => sql.includes('INSERT INTO legal_findings'))).toBe(true);
    expect(calls.some(([sql]) => sql.includes('INSERT INTO audit_log_events'))).toBe(true);
  });

  it('rejects SBOM imports that exceed the 5 MiB limit', async () => {
    db.query.mockImplementation(async (text: string) => {
      if (text.includes('FROM projects')) {
        return {
          rows: [
            {
              id: TEST_PROJECT_ID,
              tenant_id: TEST_TENANT_ID,
              name: 'Example',
              description: null,
              repo_url: null,
              oci_ref: null,
              metadata: {}
            }
          ]
        };
      }

      return { rows: [] };
    });

    const largeString = 'x'.repeat(5 * 1024 * 1024 + 10);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/sboms/import',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        format: 'CycloneDX',
        sbom: {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          metadata: { description: largeString }
        }
      }
    });

    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({ error: { code: 'payload_too_large' } });

    const calls = db.query.mock.calls as Array<Parameters<Database['query']>>;
    expect(calls.some(([sql]) => sql.includes('INSERT INTO sboms'))).toBe(false);
  });
});

