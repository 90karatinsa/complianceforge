// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';
import * as fsPromises from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

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
const TEST_SCAN_ID = '11111111-2222-4333-8444-555555555555';

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

describe('evidence pack API', () => {
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
    const auth = createAuthMocks(TEST_TENANT_ID, ['Auditor']);
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
    vi.clearAllMocks();
  });

  it('streams a stored archive from disk', async () => {
    const tempDir = await fsPromises.mkdtemp(join(tmpdir(), 'evidence-pack-'));
    const tempPath = join(tempDir, 'evidence.zip');
    await fsPromises.writeFile(tempPath, Buffer.from('ZIPDATA'));

    db.query
      .mockResolvedValueOnce({ rows: [{ id: TEST_SCAN_ID, project_id: 'project-1' }] })
      .mockResolvedValueOnce({
        rows: [
          {
            storage_path: tempPath,
            manifest: { notice_version_id: 'notice-123', feed_version: '2024.05' },
            signature: null,
            hash_algorithm: null
          }
        ]
      });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/scans/${TEST_SCAN_ID}/evidence-pack`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('application/zip');
    expect(response.body).toBe('ZIPDATA');
    expect(response.headers['x-notice-version-id']).toBe('notice-123');
    expect(response.headers['x-feed-version']).toBe('2024.05');
    expect(response.headers['cache-control']).toBe('no-store, private');
    expect(response.headers['pragma']).toBe('no-cache');
    expect(response.headers['expires']).toBe('0');
    expect(response.headers['surrogate-control']).toBe('no-store');

    await fsPromises.rm(tempDir, { recursive: true, force: true });
  });

  it('returns inline archive content when stored path is absent', async () => {
    db.query
      .mockResolvedValueOnce({ rows: [{ id: TEST_SCAN_ID, project_id: 'project-1' }] })
      .mockResolvedValueOnce({
        rows: [
          {
            storage_path: null,
            manifest: {
              inline_data: Buffer.from('INLINE').toString('base64'),
              notice_version_id: 'notice-xyz',
              feed_version: '2024.06'
            },
            signature: 'sig',
            hash_algorithm: 'sha256'
          }
        ]
      });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/scans/${TEST_SCAN_ID}/evidence-pack`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe('INLINE');
    expect(response.headers['x-notice-version-id']).toBe('notice-xyz');
    expect(response.headers['x-feed-version']).toBe('2024.06');
    expect(response.headers['cache-control']).toBe('no-store, private');
    expect(response.headers['pragma']).toBe('no-cache');
    expect(response.headers['expires']).toBe('0');
    expect(response.headers['surrogate-control']).toBe('no-store');
  });
});
