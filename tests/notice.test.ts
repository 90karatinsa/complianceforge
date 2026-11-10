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

const TEST_TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const TEST_PROJECT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const TEST_SCAN_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

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

describe('notice builder', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let noticeTimer: ReturnType<typeof vi.fn>;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisMock();
    noticeTimer = vi.fn();
    const auth = createAuthMocks(TEST_TENANT_ID, ['Legal']);
    authHeaders = auth.headers;

    metrics = {
      registry: {
        metrics: () => Promise.resolve(''),
        contentType: 'text/plain'
      },
      queueDepthGauge: { set: () => {} },
      scanDurationHistogram: { startTimer: () => () => {} },
      noticeBuildHistogram: { startTimer: () => noticeTimer },
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

  it('builds a preview document using approved licenses', async () => {
    db.query
      .mockResolvedValueOnce({ rows: [{ id: TEST_PROJECT_ID, name: 'Demo Project' }] })
      .mockResolvedValueOnce({
        rows: [
          { component_purl: 'pkg:npm/allowed@1.0.0', detected_spdx_id: 'MIT', decision: 'allow' },
          { component_purl: 'pkg:npm/pending@1.0.0', detected_spdx_id: 'Apache-2.0', decision: null }
        ]
      });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/notice/build',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        template: 'default'
      }
    });

    expect(response.statusCode).toBe(200);
    const body = response.json<{
      data: {
        document: string;
        components: Array<{ component_purl: string }>;
        version_id: string | null;
      };
    }>();
    expect(body.data.document).toContain('pkg:npm/allowed@1.0.0');
    expect(body.data.document).not.toContain('pkg:npm/pending@1.0.0');
    expect(body.data.components).toHaveLength(1);
    expect(body.data.version_id).toBeNull();
    expect(noticeTimer).toHaveBeenCalledWith({ outcome: 'preview' });
  });

  it('requires signoff metadata when finalizing', async () => {
    db.query.mockResolvedValueOnce({ rows: [{ id: TEST_PROJECT_ID, name: 'Demo Project' }] });
    db.query.mockResolvedValueOnce({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/notice/build',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        finalize: true,
        template: 'default'
      }
    });

    expect(response.statusCode).toBe(400);
    expect(noticeTimer).toHaveBeenCalledWith({ outcome: 'error' });
  });

  it('records an audit event when finalized with signoff', async () => {
    db.query
      .mockResolvedValueOnce({ rows: [{ id: TEST_PROJECT_ID, name: 'Demo Project' }] })
      .mockResolvedValueOnce({
        rows: [{ component_purl: 'pkg:npm/allowed@1.0.0', detected_spdx_id: 'MIT', decision: 'allow' }]
      })
      .mockResolvedValueOnce({ rows: [{ metadata: { active_feed_version: '2024.05' } }] })
      .mockResolvedValueOnce({ rows: [{ id: 'notice-version-1' }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValue({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/notice/build',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        project_id: TEST_PROJECT_ID,
        scan_id: TEST_SCAN_ID,
        finalize: true,
        template: 'default',
        signoff: {
          signer_name: 'Legal',
          signer_email: 'legal@example.com',
          signature: 'signed',
          payload: { office: 'HQ' }
        }
      }
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(
      expect.stringContaining('SELECT metadata FROM tenants WHERE id = $1 LIMIT 1'),
      [TEST_TENANT_ID]
    );

    const noticeInsertCall = db.query.mock.calls.find(([sql]) => sql.includes('INSERT INTO notice_versions'));
    expect(noticeInsertCall?.[1]).toEqual([
      TEST_TENANT_ID,
      TEST_PROJECT_ID,
      TEST_SCAN_ID,
      'default',
      expect.stringContaining('pkg:npm/allowed@1.0.0'),
      1,
      expect.stringMatching(/^[a-f0-9]{64}$/),
      'Legal',
      'legal@example.com',
      { office: 'HQ' },
      '2024.05'
    ]);

    const evidenceUpdate = db.query.mock.calls.find(([sql]) => sql.includes('UPDATE evidence_packs'));
    expect(evidenceUpdate?.[1]).toEqual([
      TEST_TENANT_ID,
      TEST_SCAN_ID,
      'notice-version-1',
      {
        template: 'default',
        component_count: 1,
        finalized: true,
        version_id: 'notice-version-1'
      }
    ]);

    const auditInsert = db.query.mock.calls.find(([sql]) => sql.includes('INSERT INTO audit_log_events'));
    expect(auditInsert).toBeDefined();
    const auditPayload = auditInsert?.[1]?.[6] as Record<string, unknown> | undefined;
    expect(auditPayload?.notice_version_id).toBe('notice-version-1');
    expect(auditPayload?.feed_version).toBe('2024.05');

    const body = response.json<{
      data: { version_id: string | null };
    }>();
    expect(body.data.version_id).toBe('notice-version-1');
    expect(noticeTimer).toHaveBeenCalledWith({ outcome: 'finalized' });
  });
});
