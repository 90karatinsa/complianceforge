// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.js';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: class {
    send = vi.fn();
  },
  GetSecretValueCommand: class {}
}));

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
const PROJECT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ARTIFACT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const TEST_VERSION = '1.0.0-test';
const VALID_SHA256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

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
    purgeDurationHistogram: { startTimer: () => () => {} }
  } satisfies Metrics;
}

describe('artifacts endpoint', () => {
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
    const auth = createAuthMocks(TEST_TENANT_ID);
    authHeaders = auth.headers;
    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      generateId: () => ARTIFACT_ID,
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

  it('creates an artifact for a project', async () => {
    db.query.mockResolvedValueOnce({ rows: [{ id: PROJECT_ID }] });
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: ARTIFACT_ID,
          project_id: PROJECT_ID,
          type: 'git',
          ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
          metadata: { labels: ['release'] },
          created_at: '2024-01-01T00:00:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'git',
        ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
        metadata: { labels: ['release'] }
      }
    });

    expect(response.statusCode).toBe(201);
    expect(db.query.mock.calls[0]).toEqual([
      'SELECT id FROM projects WHERE id = $1 AND tenant_id = $2 LIMIT 1',
      [PROJECT_ID, TEST_TENANT_ID]
    ]);
    expect(db.query.mock.calls[1][0]).toContain('INSERT INTO artifacts');
    expect(db.query.mock.calls[1][1]).toEqual([
      ARTIFACT_ID,
      PROJECT_ID,
      'git',
      { url: 'https://example.com/repo.git', commit: 'abc123' },
      { labels: ['release'] }
    ]);
    expect(response.json()).toEqual({
      data: {
        id: ARTIFACT_ID,
        project_id: PROJECT_ID,
        type: 'git',
        ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
        metadata: { labels: ['release'] },
        created_at: '2024-01-01T00:00:00.000Z'
      }
    });
  });

  it('validates ref fields for each type', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'git',
        ref: {}
      }
    });

    expect(response.statusCode).toBe(400);
    expect(db.query).not.toHaveBeenCalled();
  });

  it('rejects git artifacts with unsupported urls', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'git',
        ref: { url: 'http://example.com/repo.git', commit: 'abc123' }
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Git artifacts require an https or ssh url reference.'
      }
    });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('allows git artifacts with ssh style urls', async () => {
    db.query.mockResolvedValueOnce({ rows: [{ id: PROJECT_ID }] });
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: ARTIFACT_ID,
          project_id: PROJECT_ID,
          type: 'git',
          ref: { url: 'git@example.com:repo.git', branch: 'main' },
          metadata: null,
          created_at: '2024-01-01T00:00:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'git',
        ref: { url: 'git@example.com:repo.git', branch: 'main' }
      }
    });

    expect(response.statusCode).toBe(201);
  });

  it('normalizes git artifact references before persistence', async () => {
    db.query.mockResolvedValueOnce({ rows: [{ id: PROJECT_ID }] });
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: ARTIFACT_ID,
          project_id: PROJECT_ID,
          type: 'git',
          ref: { url: 'https://example.com/repo.git', branch: 'main' },
          metadata: null,
          created_at: '2024-01-01T00:00:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'git',
        ref: { url: '  https://example.com/repo.git  ', branch: '  main  ' }
      }
    });

    expect(response.statusCode).toBe(201);
    expect(db.query).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('INSERT INTO artifacts'),
      [
        ARTIFACT_ID,
        PROJECT_ID,
        'git',
        { url: 'https://example.com/repo.git', branch: 'main' },
        {}
      ]
    );
  });

  it('rejects archive artifacts with non-HTTPS urls', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'archive',
        ref: { url: 'http://example.com/archive.tgz', sha256: VALID_SHA256 }
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Archive artifacts require an https url reference.'
      }
    });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('rejects archive artifacts without sha256 digests', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'archive',
        ref: { url: 'https://example.com/archive.tgz' }
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Archive artifacts require a sha256 digest reference.'
      }
    });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('rejects archive artifacts with malformed sha256 digests', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'archive',
        ref: { url: 'https://example.com/archive.tgz', sha256: 'ABC' }
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Archive artifact sha256 digests must be 64 lowercase hex characters.'
      }
    });
    expect(db.query).not.toHaveBeenCalled();
  });

  it('returns 404 when the project is missing', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'archive',
        ref: { url: 'https://example.com/archive.tgz', sha256: VALID_SHA256 }
      }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({
      error: {
        code: 'not_found',
        message: 'Owning project not found.'
      }
    });
  });

  it('accepts archive artifacts with valid sha256 digests', async () => {
    db.query.mockResolvedValueOnce({ rows: [{ id: PROJECT_ID }] });
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: ARTIFACT_ID,
          project_id: PROJECT_ID,
          type: 'archive',
          ref: { url: 'https://example.com/archive.tgz', sha256: VALID_SHA256 },
          metadata: null,
          created_at: '2024-01-01T00:00:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/artifacts',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        type: 'archive',
        ref: { url: 'https://example.com/archive.tgz', sha256: VALID_SHA256 }
      }
    });

    expect(response.statusCode).toBe(201);
  });
});
