// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.js';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: class {
    send = vi.fn();
  },
  GetSecretValueCommand: class {}
}));

vi.mock('keytar', () => ({
  getPassword: vi.fn().mockResolvedValue(null),
  setPassword: vi.fn().mockResolvedValue(undefined),
  deletePassword: vi.fn().mockResolvedValue(true)
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

const TEST_VERSION = '0.0.0-test';
const TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROJECT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ARTIFACT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const GENERATED_ARTIFACT_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const SCAN_ID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const RETRY_SCAN_ID = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const SBOM_SCAN_ID = '11111111-2222-4333-8444-555555555555';
const IDEMPOTENCY_HEADER = 'Idempotency-Key';
const DEFAULT_IDEMPOTENCY_KEY = 'test-idempotency-key';

function createDbMock(): { query: ReturnType<typeof vi.fn> } & Database {
  const query = vi.fn();
  return { query } as { query: ReturnType<typeof vi.fn> } & Database;
}

function createQueueMock(): { add: ReturnType<typeof vi.fn>; getJobCounts: ReturnType<typeof vi.fn> } & JobQueue {
  const add = vi.fn().mockResolvedValue(undefined);
  const getJobCounts = vi.fn().mockResolvedValue({ waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0 });
  return { add, getJobCounts } as { add: ReturnType<typeof vi.fn>; getJobCounts: ReturnType<typeof vi.fn> } & JobQueue;
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

function expectedLinks(scanId: string) {
  return {
    self: `/v1/scans/${scanId}`,
    sbom: `/v1/sboms/${scanId}`,
    vulns: `/v1/vulns?scan_id=${scanId}`,
    licenses: `/v1/licenses?scan_id=${scanId}`
  };
}

function handleCommonDbQueries(text: string) {
  if (text.startsWith('DELETE FROM scans WHERE id = $1')) {
    return { rows: [] };
  }

  if (text.startsWith('DELETE FROM scan_requests WHERE id = $1')) {
    return { rows: [] };
  }

  if (text.startsWith('INSERT INTO audit_log_events')) {
    return { rows: [] };
  }

  return null;
}

describe('scans endpoints', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let idSequence: string[];
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    db = createDbMock();
    queue = createQueueMock();
    idSequence = [];
    redis = createRedisMock();
    metrics = createMetricsStub();
    const auth = createAuthMocks(TENANT_ID);
    authHeaders = {
      ...auth.headers,
      [IDEMPOTENCY_HEADER]: DEFAULT_IDEMPOTENCY_KEY
    };
    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      generateId: () => {
        if (idSequence.length === 0) {
          throw new Error('Unexpected id request');
        }

        return idSequence.shift() as string;
      },
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: auth.lookupApiKey,
      licenseStatusProvider: vi.fn().mockResolvedValue({
        status: 'active',
        licenseId: 'test-license',
        warnings: [],
        features: ['scan:execute']
      })
    });
  });

  afterEach(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it('creates a scan for an existing artifact and enqueues a job', async () => {
    idSequence = [SCAN_ID];

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: 'tenant-1',
              name: 'demo',
              description: null,
              repo_url: 'https://example.com/repo.git',
              oci_ref: null,
              metadata: {}
            }
          ]
        });
      }

      if (text.startsWith('SELECT id FROM artifacts')) {
        return Promise.resolve({ rows: [{ id: ARTIFACT_ID }] });
      }

      if (text.startsWith('INSERT INTO scan_requests')) {
        return Promise.resolve({ rows: [{ id: 'request-1' }] });
      }

      if (text.startsWith('INSERT INTO scans')) {
        return Promise.resolve({
          rows: [
            {
              id: SCAN_ID,
              project_id: PROJECT_ID,
              artifact_id: ARTIFACT_ID,
              policy_id: null,
              policy_result: null,
              status: 'queued',
              findings: {},
              duration_ms: null,
              started_at: '2024-01-01T00:00:00.000Z',
              completed_at: null,
              created_at: '2024-01-01T00:00:00.000Z'
            }
          ]
        });
      }

      if (text.startsWith('UPDATE scan_requests')) {
        return Promise.resolve({ rows: [] });
      }

      throw new Error(`Unexpected query: ${text}`);
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID
      }
    });

    expect(response.statusCode).toBe(201);
    expect(queue.add).toHaveBeenCalledWith('scan', {
      scan_id: SCAN_ID,
      project_id: PROJECT_ID,
      artifact_id: ARTIFACT_ID,
      policy_id: null
    });
    expect(response.json()).toEqual({
      data: {
        id: SCAN_ID,
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID,
        policy_id: null,
        policy_result: null,
        status: 'queued',
        findings: {},
        duration_ms: null,
        started_at: '2024-01-01T00:00:00.000Z',
        completed_at: null,
        created_at: '2024-01-01T00:00:00.000Z',
        links: expectedLinks(SCAN_ID)
      }
    });
  });

  it('auto-creates a git artifact from the project repo metadata when none is provided', async () => {
    idSequence = [GENERATED_ARTIFACT_ID, SCAN_ID];

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: 'tenant-1',
              name: 'demo',
              description: null,
              repo_url: 'https://example.com/repo.git',
              oci_ref: null,
              metadata: { default_branch: 'develop' }
            }
          ]
        });
      }

      if (text.startsWith('INSERT INTO scan_requests')) {
        return Promise.resolve({ rows: [{ id: 'request-2' }] });
      }

      if (text.startsWith('INSERT INTO artifacts')) {
        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('INSERT INTO scans')) {
        return Promise.resolve({
          rows: [
            {
              id: SCAN_ID,
              project_id: PROJECT_ID,
              artifact_id: GENERATED_ARTIFACT_ID,
              policy_id: null,
              policy_result: null,
              status: 'queued',
              findings: {},
              duration_ms: null,
              started_at: '2024-01-01T00:00:00.000Z',
              completed_at: null,
              created_at: '2024-01-01T00:00:00.000Z'
            }
          ]
        });
      }

      if (text.startsWith('UPDATE scan_requests')) {
        return Promise.resolve({ rows: [] });
      }

      throw new Error(`Unexpected query: ${text}`);
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID
      }
    });

    expect(response.statusCode).toBe(201);
    const queryCalls = db.query.mock.calls as Array<Parameters<Database['query']>>;
    const insertCall = queryCalls.find(([sql]) => sql.includes('INSERT INTO artifacts'));
    expect(insertCall?.[1]).toEqual([
      GENERATED_ARTIFACT_ID,
      PROJECT_ID,
      'git',
      { url: 'https://example.com/repo.git', branch: 'develop' },
      { source: 'project' }
    ]);
    expect(queue.add).toHaveBeenCalledWith('scan', {
      scan_id: SCAN_ID,
      project_id: PROJECT_ID,
      artifact_id: GENERATED_ARTIFACT_ID,
      policy_id: null
    });
  });

  it('auto-creates an OCI artifact when the project defines an oci_ref', async () => {
    idSequence = [GENERATED_ARTIFACT_ID, SCAN_ID];

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: 'tenant-1',
              name: 'demo',
              description: null,
              repo_url: null,
              oci_ref: 'registry.example.com/team/app:1.2.3',
              metadata: {}
            }
          ]
        });
      }

      if (text.startsWith('INSERT INTO scan_requests')) {
        return Promise.resolve({ rows: [{ id: 'request-3' }] });
      }

      if (text.startsWith('INSERT INTO artifacts')) {
        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('INSERT INTO scans')) {
        return Promise.resolve({
          rows: [
            {
              id: SCAN_ID,
              project_id: PROJECT_ID,
              artifact_id: GENERATED_ARTIFACT_ID,
              policy_id: null,
              policy_result: null,
              status: 'queued',
              findings: {},
              duration_ms: null,
              started_at: '2024-01-01T00:00:00.000Z',
              completed_at: null,
              created_at: '2024-01-01T00:00:00.000Z'
            }
          ]
        });
      }

      if (text.startsWith('UPDATE scan_requests')) {
        return Promise.resolve({ rows: [] });
      }

      throw new Error(`Unexpected query: ${text}`);
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID
      }
    });

    expect(response.statusCode).toBe(201);
    const queryCalls = db.query.mock.calls as Array<Parameters<Database['query']>>;
    const insertCall = queryCalls.find(([sql]) => sql.includes('INSERT INTO artifacts'));
    expect(insertCall?.[1]).toEqual([
      GENERATED_ARTIFACT_ID,
      PROJECT_ID,
      'oci',
      {
        registry: 'registry.example.com',
        repository: 'team/app',
        tag: '1.2.3',
        digest: undefined
      },
      { source: 'project' }
    ]);
  });

  it('returns a validation error when the project lacks artifact metadata', async () => {
    idSequence = [SCAN_ID];

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: 'tenant-1',
              name: 'demo',
              description: null,
              repo_url: null,
              oci_ref: null,
              metadata: {}
            }
          ]
        });
      }

      return Promise.resolve({ rows: [] });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('rejects archive artifacts with non-HTTPS urls when creating scans', async () => {
    db.query.mockImplementationOnce(() =>
      Promise.resolve({
        rows: [
          {
            id: PROJECT_ID,
            tenant_id: TENANT_ID,
            name: 'demo',
            description: null,
            repo_url: null,
            oci_ref: null,
            metadata: {}
          }
        ]
      })
    );

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact: {
          type: 'archive',
          ref: { url: 'http://example.com/archive.tgz' }
        }
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Archive artifacts require an https url reference.'
      }
    });
    expect(db.query).toHaveBeenCalledTimes(1);
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('validates policy identifiers', async () => {
    idSequence = [SCAN_ID];

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: 'tenant-1',
              name: 'demo',
              description: null,
              repo_url: 'https://example.com/repo.git',
              oci_ref: null,
              metadata: {}
            }
          ]
        });
      }

      if (text.startsWith('SELECT id FROM policies')) {
        return Promise.resolve({ rows: [] });
      }

      return Promise.resolve({ rows: [] });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID,
        policy_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
      }
    });

    expect(response.statusCode).toBe(404);
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('requires an Idempotency-Key header', async () => {
    idSequence = [SCAN_ID];

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: 'tenant-1',
              name: 'demo',
              description: null,
              repo_url: 'https://example.com/repo.git',
              oci_ref: null,
              metadata: {}
            }
          ]
        });
      }

      if (text.startsWith('SELECT id FROM artifacts')) {
        return Promise.resolve({ rows: [{ id: ARTIFACT_ID }] });
      }

      throw new Error(`Unexpected query: ${text}`);
    });

    const { [IDEMPOTENCY_HEADER]: _ignored, ...headersWithoutKey } = authHeaders;

    const response = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: headersWithoutKey,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: { code: 'validation_error', message: expect.stringContaining('Idempotency-Key') }
    });
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('returns an existing scan when the same Idempotency-Key is reused', async () => {
    idSequence = [SCAN_ID];

    let scanRequestClaimed = false;

    db.query.mockImplementation((text: string) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: TENANT_ID,
              name: 'demo',
              description: null,
              repo_url: 'https://example.com/repo.git',
              oci_ref: null,
              metadata: {}
            }
          ]
        });
      }

      if (text.startsWith('SELECT id FROM artifacts')) {
        return Promise.resolve({ rows: [{ id: ARTIFACT_ID }] });
      }

      if (text.startsWith('INSERT INTO scan_requests')) {
        if (!scanRequestClaimed) {
          scanRequestClaimed = true;
          return Promise.resolve({ rows: [{ id: 'request-duplicate' }] });
        }

        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('INSERT INTO scans')) {
        return Promise.resolve({
          rows: [
            {
              id: SCAN_ID,
              project_id: PROJECT_ID,
              artifact_id: ARTIFACT_ID,
              policy_id: null,
              policy_result: null,
              status: 'queued',
              findings: {},
              duration_ms: null,
              started_at: '2024-01-01T00:00:00.000Z',
              completed_at: null,
              created_at: '2024-01-01T00:00:00.000Z'
            }
          ]
        });
      }

      if (text.startsWith('UPDATE scan_requests')) {
        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('SELECT scan_id FROM scan_requests')) {
        return Promise.resolve({ rows: [{ scan_id: SCAN_ID }] });
      }

      if (text.startsWith('SELECT s.id, s.project_id')) {
        return Promise.resolve({
          rows: [
            {
              id: SCAN_ID,
              project_id: PROJECT_ID,
              artifact_id: ARTIFACT_ID,
              policy_id: null,
              policy_result: null,
              status: 'queued',
              findings: {},
              duration_ms: null,
              started_at: '2024-01-01T00:00:00.000Z',
              completed_at: null,
              created_at: '2024-01-01T00:00:00.000Z'
            }
          ]
        });
      }

      throw new Error(`Unexpected query: ${text}`);
    });

    const firstResponse = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID
      }
    });

    expect(firstResponse.statusCode).toBe(201);
    expect(queue.add).toHaveBeenCalledTimes(1);

    const retryResponse = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID
      }
    });

    expect(retryResponse.statusCode).toBe(200);
    expect(retryResponse.json()).toEqual(firstResponse.json());
    expect(queue.add).toHaveBeenCalledTimes(1);
  });

  it('cleans up scan claim when queue enqueue fails and allows retry', async () => {
    idSequence = [SCAN_ID, RETRY_SCAN_ID];

    let firstClaimId: string | null = null;
    let secondClaimId: string | null = null;

    queue.add
      .mockRejectedValueOnce(new Error('queue unavailable'))
      .mockResolvedValueOnce(undefined);

    db.query.mockImplementation((text: string, values?: ReadonlyArray<unknown>) => {
      const handled = handleCommonDbQueries(text);
      if (handled) {
        return Promise.resolve(handled);
      }

      if (text.startsWith('SELECT id, tenant_id')) {
        return Promise.resolve({
          rows: [
            {
              id: PROJECT_ID,
              tenant_id: TENANT_ID,
              name: 'demo',
              description: null,
              repo_url: 'https://example.com/repo.git',
              oci_ref: null,
              metadata: {}
            }
          ]
        });
      }

      if (text.startsWith('SELECT id FROM artifacts')) {
        return Promise.resolve({ rows: [{ id: ARTIFACT_ID }] });
      }

      if (text.startsWith('INSERT INTO scan_requests')) {
        const insertedId = values?.[0] as string;
        if (!firstClaimId) {
          firstClaimId = insertedId;
        } else if (!secondClaimId) {
          secondClaimId = insertedId;
        }
        return Promise.resolve({ rows: [{ id: insertedId }] });
      }

      if (text.startsWith('INSERT INTO scans')) {
        const insertedId = values?.[0];
        return Promise.resolve({
          rows: [
            {
              id: insertedId,
              project_id: PROJECT_ID,
              artifact_id: ARTIFACT_ID,
              policy_id: null,
              policy_result: null,
              status: 'queued',
              findings: {},
              duration_ms: null,
              started_at: '2024-01-01T00:00:00.000Z',
              completed_at: null,
              created_at: '2024-01-01T00:00:00.000Z'
            }
          ]
        });
      }

      if (text.startsWith('UPDATE scan_requests')) {
        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('DELETE FROM scan_requests')) {
        return Promise.resolve({ rows: [] });
      }

      if (text.startsWith('DELETE FROM scans')) {
        return Promise.resolve({ rows: [] });
      }

      throw new Error(`Unexpected query: ${text}`);
    });

    const firstResponse = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID
      }
    });

    expect(firstResponse.statusCode).toBe(500);
    expect(queue.add).toHaveBeenCalledTimes(1);
    expect(firstClaimId).not.toBeNull();
    expect(db.query).toHaveBeenCalledWith('DELETE FROM scan_requests WHERE id = $1', [firstClaimId]);
    expect(db.query).toHaveBeenCalledWith('DELETE FROM scans WHERE id = $1', [SCAN_ID]);

    const retryResponse = await app.inject({
      method: 'POST',
      url: '/v1/scans',
      headers: authHeaders,
      payload: {
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID
      }
    });

    expect(retryResponse.statusCode).toBe(201);
    expect(queue.add).toHaveBeenCalledTimes(2);
    expect(secondClaimId).not.toBeNull();
    expect(retryResponse.json()).toMatchObject({
      data: {
        id: RETRY_SCAN_ID
      }
    });
  });

  it('lists scans with normalized policy results and pagination', async () => {
    db.query.mockImplementationOnce(() =>
      Promise.resolve({
        rows: [
          {
            id: SCAN_ID,
            project_id: PROJECT_ID,
            artifact_id: ARTIFACT_ID,
            policy_id: null,
            policy_result: 'allowed',
            status: 'complete',
            findings: {},
            duration_ms: '2500',
            started_at: '2024-01-02T00:00:00.000Z',
            completed_at: '2024-01-02T00:05:00.000Z',
            created_at: '2024-01-02T00:00:00.000Z',
            total_count: '42'
          }
        ]
      })
    );

    const response = await app.inject({
      method: 'GET',
      url: '/v1/scans',
      headers: authHeaders,
      query: {
        project_id: PROJECT_ID,
        policy_result: 'pass',
        page: '2',
        page_size: '10'
      }
    });

    const listCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('FROM scans s') && sql.includes('ORDER BY')
    );
    expect(listCall?.[0]).toContain('ORDER BY s.created_at DESC, s.id DESC');

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: [
        {
          id: SCAN_ID,
          project_id: PROJECT_ID,
          artifact_id: ARTIFACT_ID,
          policy_id: null,
          policy_result: 'pass',
          status: 'complete',
          findings: {},
          duration_ms: 2500,
          started_at: '2024-01-02T00:00:00.000Z',
          completed_at: '2024-01-02T00:05:00.000Z',
          created_at: '2024-01-02T00:00:00.000Z',
          links: expectedLinks(SCAN_ID)
        }
      ],
      pagination: {
        page: 2,
        page_size: 10,
        count: 1,
        total: 42
      }
    });
  });

  it('returns a zero total when no scans match the filters', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });
    db.query.mockResolvedValueOnce({ rows: [{ total: '0' }] });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/scans',
      headers: authHeaders,
      query: {
        page: '1',
        page_size: '5'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: [],
      pagination: {
        page: 1,
        page_size: 5,
        count: 0,
        total: 0
      }
    });
  });

  it('returns the actual total when the requested page is empty', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });
    db.query.mockResolvedValueOnce({ rows: [{ total: '23' }] });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/scans',
      headers: authHeaders,
      query: {
        page: '3',
        page_size: '10'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: [],
      pagination: {
        page: 3,
        page_size: 10,
        count: 0,
        total: 23
      }
    });
  });

  it('retrieves a scan by id and normalizes pending results', async () => {
    db.query.mockImplementationOnce(() =>
      Promise.resolve({
        rows: [
        {
          id: SCAN_ID,
          project_id: PROJECT_ID,
          artifact_id: ARTIFACT_ID,
          policy_id: null,
          policy_result: 'pending',
          status: 'queued',
          findings: {},
          duration_ms: null,
          started_at: '2024-01-01T00:00:00.000Z',
          completed_at: null,
          created_at: '2024-01-01T00:00:00.000Z'
        }
      ]
      })
    );

    const response = await app.inject({
      method: 'GET',
      url: `/v1/scans/${SCAN_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: {
        id: SCAN_ID,
        project_id: PROJECT_ID,
        artifact_id: ARTIFACT_ID,
        policy_id: null,
        policy_result: 'warn',
        status: 'queued',
        findings: {},
        duration_ms: null,
        started_at: '2024-01-01T00:00:00.000Z',
        completed_at: null,
        created_at: '2024-01-01T00:00:00.000Z',
        links: expectedLinks(SCAN_ID)
      }
    });
  });

  it('returns 404 when a scan cannot be found', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/scans/${SCAN_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'not_found' } });
  });

  it('returns the latest SBOM for a scan', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          format: 'CycloneDX',
          bom: { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1 }
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/sboms/${SBOM_SCAN_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('application/vnd.cyclonedx+json');
    expect(response.json()).toEqual({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1 });
  });

  it('returns 404 when requesting an SBOM for an unknown scan', async () => {
    db.query.mockResolvedValueOnce({ rows: [] });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/sboms/${SBOM_SCAN_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'not_found' } });
  });

  it('lists vulnerabilities with filters applied', async () => {
    db.query.mockResolvedValueOnce({
      rows: [
        {
          id: 'vuln-1',
          scan_id: SCAN_ID,
          component_purl: 'pkg:npm/left-pad@1.0.0',
          source: 'osv',
          cve_id: 'CVE-0000-0001',
          severity: 'high',
          cvss: '7.5',
          summary: 'Example vulnerability',
          fixed_version: '1.0.1',
          detected_at: '2024-01-03T00:00:00.000Z'
        }
      ]
    });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/vulns',
      headers: authHeaders,
      query: {
        scan_id: SCAN_ID,
        severity: 'high',
        component_purl: 'pkg:npm/left-pad@1.0.0',
        cvss_min: '7',
        page: '1',
        page_size: '5'
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      data: [
        {
          id: 'vuln-1',
          scan_id: SCAN_ID,
          component_purl: 'pkg:npm/left-pad@1.0.0',
          source: 'osv',
          cve_id: 'CVE-0000-0001',
          severity: 'high',
          cvss: 7.5,
          summary: 'Example vulnerability',
          fixed_version: '1.0.1',
          detected_at: '2024-01-03T00:00:00.000Z'
        }
      ],
      pagination: {
        page: 1,
        page_size: 5,
        count: 1
      }
    });
  });
});
