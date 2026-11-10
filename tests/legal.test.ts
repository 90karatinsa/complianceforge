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

const TEST_VERSION = '0.0.0-test';
const TEST_TENANT_ID = '11111111-1111-4111-8111-111111111111';
const TEST_FINDING_ID = '22222222-2222-4222-8222-222222222222';
const TEST_DECISION_ID = '33333333-3333-4333-8333-333333333333';
const TEST_SIGNOFF_ID = '44444444-4444-4444-8444-444444444444';

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
}

describe('legal endpoints', () => {
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
    const auth = createAuthMocks(TEST_TENANT_ID, ['Legal']);
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

  it('lists legal findings with latest decision metadata', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: TEST_FINDING_ID,
          tenant_id: TEST_TENANT_ID,
          license_id: 'license-1',
          vuln_id: null,
          scan_id: 'scan-1',
          status: 'pending',
          obligations: { notice: true },
          notes: 'needs review',
          created_at: '2024-01-01T00:00:00.000Z',
          decision: null,
          decided_at: null,
          rationale: null
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/legal/findings?tenant_id=${TEST_TENANT_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(expect.stringContaining('FROM legal_findings'), [
      TEST_TENANT_ID,
      'pending',
      20,
      0
    ]);
    expect(response.json()).toMatchObject({
      data: [
        {
          id: TEST_FINDING_ID,
          status: 'pending',
          obligations: { notice: true },
          notes: 'needs review',
          scan_id: 'scan-1',
          license_id: 'license-1'
        }
      ],
      pagination: { page: 1, page_size: 20 }
    });
  });

  it('records a legal decision with signoff metadata', async () => {
    db.query
      .mockResolvedValueOnce({
        rows: [{ id: TEST_FINDING_ID, scan_id: 'scan-1', project_id: 'project-1' }]
      })
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_DECISION_ID,
            tenant_id: TEST_TENANT_ID,
            finding_id: TEST_FINDING_ID,
            decision: 'allow',
            rationale: 'Compliant',
            decided_by: 'api-key-1',
            decided_at: '2024-01-02T00:00:00.000Z',
            expires_at: null,
            metadata: {}
          }
        ]
      })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_SIGNOFF_ID,
            tenant_id: TEST_TENANT_ID,
            decision_id: TEST_DECISION_ID,
            signer_name: 'Legal Reviewer',
            signer_email: 'legal@example.com',
            signature_hash: 'abc123',
            signature_payload: {},
            signed_at: '2024-01-02T00:05:00.000Z'
          }
        ]
      })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/legal/decisions',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        finding_id: TEST_FINDING_ID,
        decision: 'allow',
        rationale: 'Compliant',
        metadata: { note: 'approved' },
        signoff: {
          signer_name: 'Legal Reviewer',
          signer_email: 'legal@example.com',
          signature: 'signed',
          payload: { location: 'Ankara' }
        }
      }
    });

    expect(response.statusCode).toBe(201);
    const signoffCall = db.query.mock.calls.find((call) => {
      const [sql] = call;
      return typeof sql === 'string' && sql.includes('INSERT INTO legal_signoffs');
    });

    expect(signoffCall).toBeDefined();
    const signoffValues = signoffCall?.[1] as unknown[] | undefined;
    expect(signoffValues?.[1]).toBe(TEST_TENANT_ID);
    expect(signoffValues?.[2]).toBe(TEST_DECISION_ID);
    expect(signoffValues?.[3]).toBe('Legal Reviewer');
    expect(signoffValues?.[4]).toBe('legal@example.com');
    const body = response.json<{ data: { decision: unknown; signoff: { signer_name: string } } }>();
    expect(body.data.signoff?.signer_name).toBe('Legal Reviewer');
  });
});
