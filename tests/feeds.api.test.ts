// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildServer,
  type Database,
  type DatabaseClient,
  type JobQueue,
  type RedisConnection
} from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { MAX_FEED_ARCHIVE_BYTES } from '../scripts/feed-manifest.ts';
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
    public send = vi.fn();
  },
  GetSecretValueCommand: class {
    public readonly input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  }
}));

const recordUpdateLogEntryMock = vi.hoisted(() => vi.fn());

vi.mock('../observability/update-log.ts', () => ({
  recordUpdateLogEntry: recordUpdateLogEntryMock
}));

const TEST_TENANT_ID = '55555555-5555-4555-8555-555555555555';
const TEST_MANIFEST_ID = '66666666-6666-4666-8666-666666666666';

interface DbMock extends Database {
  query: ReturnType<typeof vi.fn>;
  transaction: ReturnType<typeof vi.fn>;
  clientQueries: Array<ReturnType<typeof vi.fn>>;
}

function createDbMock(): DbMock {
  const query = vi.fn();
  const clientQueries: Array<ReturnType<typeof vi.fn>> = [];
  const transaction = vi.fn(async (handler: (client: DatabaseClient) => Promise<unknown>) => {
    const clientQuery = vi.fn(async (sql: string, values?: ReadonlyArray<unknown>) =>
      query(sql, values)
    );
    clientQueries.push(clientQuery);
    return handler({ query: clientQuery });
  });

  return { query, transaction, clientQueries } as unknown as DbMock;
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

describe('feed management API', () => {
  let db: DbMock;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let feedCounter: ReturnType<typeof vi.fn>;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;

  beforeEach(async () => {
    recordUpdateLogEntryMock.mockReset();
    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisMock();
    feedCounter = vi.fn();
    const auth = createAuthMocks(TEST_TENANT_ID, ['Admin']);
    authHeaders = auth.headers;

    metrics = {
      registry: { metrics: () => Promise.resolve(''), contentType: 'text/plain' },
      queueDepthGauge: { set: () => {} },
      scanDurationHistogram: { startTimer: () => () => {} },
      noticeBuildHistogram: { startTimer: () => () => {} },
      webhookOutcomeCounter: { inc: () => {} },
      feedImportCounter: { inc: feedCounter },
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

  it('uploads a feed manifest and populates cached vulnerabilities', async () => {
    const manifest = {
      feed_version: '2024.07',
      minimum_downgrade_version: '2024.06',
      packages: [
        {
          filename: 'osv-2024-07.json',
          sha256: 'a'.repeat(64),
          size_bytes: 2048,
          stored_at: 's3://feeds/osv-2024-07.json'
        }
      ],
      vulnerabilities: [
        {
          package_purl: 'pkg:npm/lodash@4.17.21',
          vulnerabilities: [{ id: 'OSV-2024-0001', summary: 'Example' }],
          fetched_at: '2024-07-01T00:00:00.000Z'
        }
      ]
    } satisfies Record<string, unknown>;

    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('RETURNING id')) {
        return { rows: [{ id: TEST_MANIFEST_ID }] };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/upload',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        version: '2024.07',
        manifest,
        signature: null
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      manifest_id: TEST_MANIFEST_ID,
      version: '2024.07',
      package_count: 1,
      vulnerability_count: 1,
      signature_verified: false
    });

    expect(feedCounter).toHaveBeenCalledWith({ action: 'upload' });

    const manifestCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO feed_manifests')
    );
    expect(manifestCall?.[1]).toEqual([TEST_TENANT_ID, '2024.07', manifest, null, null]);

    const packageCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO feed_packages')
    );
    expect(packageCall?.[1]).toEqual([
      TEST_TENANT_ID,
      TEST_MANIFEST_ID,
      'osv-2024-07.json',
      'a'.repeat(64),
      2048,
      's3://feeds/osv-2024-07.json'
    ]);

    const osvCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO osv_cache')
    );
    expect(osvCall?.[1]).toEqual([
      TEST_TENANT_ID,
      'pkg:npm/lodash@4.17.21',
      '2024.07',
      [{ id: 'OSV-2024-0001', summary: 'Example' }],
      new Date('2024-07-01T00:00:00.000Z')
    ]);

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    const auditPayload = auditCall?.[1]?.[6] as Record<string, unknown> | undefined;
    expect(auditPayload).toMatchObject({
      manifest_id: TEST_MANIFEST_ID,
      version: '2024.07',
      package_count: 1,
      vulnerability_count: 1,
      signature_present: false,
      signature_verified: false
    });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.upload',
        manifest_id: TEST_MANIFEST_ID,
        version: '2024.07',
        actor: expect.stringMatching(/^api_key:/u),
        result: 'success',
        metadata: expect.objectContaining({
          signature_present: false,
          signature_verified: false,
          minimum_downgrade_version: '2024.06'
        })
      })
    );

    expect(db.transaction).toHaveBeenCalledTimes(1);
    expect(db.clientQueries).toHaveLength(1);
    const transactionalCalls = db.clientQueries[0]?.mock.calls ?? [];
    const executedSql = transactionalCalls.map(([sql]) => String(sql));
    expect(executedSql.some((sql) => sql.includes('INSERT INTO feed_manifests'))).toBe(true);
    expect(executedSql.some((sql) => sql.includes('DELETE FROM feed_packages'))).toBe(true);
    expect(executedSql.some((sql) => sql.includes('INSERT INTO feed_packages'))).toBe(true);
    expect(executedSql.some((sql) => sql.includes('DELETE FROM osv_cache'))).toBe(true);
    expect(executedSql.some((sql) => sql.includes('INSERT INTO osv_cache'))).toBe(true);
  });

  it('rejects unsigned feed uploads when a public key is configured', async () => {
    await app.close();

    db.query.mockResolvedValue({ rows: [] });

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
      licenseStatusProvider: createLicenseStatusProvider(),
      feedPublicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----'
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/upload',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        version: '2024.08',
        manifest: { feed_version: '2024.08', minimum_downgrade_version: '2024.07', packages: [], vulnerabilities: [] },
        signature: null
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation_error',
        message: 'Signature required when feed public key is configured.'
      }
    });
    expect(
      db.query
    ).not.toHaveBeenCalledWith(expect.stringContaining('INSERT INTO feed_manifests'));

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.upload',
        manifest_id: null,
        result: 'failure',
        metadata: expect.objectContaining({ reason: 'signature_verification_failed' })
      })
    );
  });

  it('rejects feed uploads that exceed the manifest size limit', async () => {
    db.query.mockResolvedValue({ rows: [] });

    const oversizeManifest = {
      feed_version: '2024.10',
      packages: [],
      vulnerabilities: [],
      padding: 'y'.repeat(MAX_FEED_ARCHIVE_BYTES + 1)
    } satisfies Record<string, unknown>;

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/upload',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        version: '2024.10',
        manifest: oversizeManifest,
        signature: null
      }
    });

    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({ message: /maximum size/i });

    expect(recordUpdateLogEntryMock).not.toHaveBeenCalled();
  });

  it('lists imported manifests and active version', async () => {
    db.query
      .mockResolvedValueOnce({
        rows: [
          {
            id: TEST_MANIFEST_ID,
            version: '2024.01',
            manifest: {
              feed_version: '2024.01',
              packages: [],
              vulnerabilities: [],
              minimum_downgrade_version: '2023.12'
            },
            imported_at: '2024-01-01T00:00:00.000Z',
            verified_at: null,
            signature: null
          }
        ]
      })
      .mockResolvedValueOnce({ rows: [{ metadata: { active_feed_version: '2024.01' } }] })
      .mockResolvedValueOnce({
        rows: [
          {
            manifest: {
              feed_version: '2024.01',
              packages: [],
              vulnerabilities: [],
              minimum_downgrade_version: '2023.12'
            }
          }
        ]
      });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/feeds?tenant_id=${TEST_TENANT_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenNthCalledWith(1, expect.stringContaining('FROM feed_manifests'), [
      TEST_TENANT_ID,
      50,
      0
    ]);
    const body = response.json();
    expect(body).toMatchObject({
      active_version: '2024.01',
      active_minimum_downgrade_version: '2023.12'
    });
    expect(body.data?.[0]).toMatchObject({
      id: TEST_MANIFEST_ID,
      minimum_downgrade_version: '2023.12'
    });
  });

  it('derives the downgrade floor from the newest manifest when tenant metadata is stale', async () => {
    let manifestQuerySql: string | undefined;

    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('FROM feed_manifests') && sql.includes('LIMIT $2 OFFSET $3')) {
        return {
          rows: [
            {
              id: 'manifest-newer',
              version: '2024.02',
              manifest: {
                feed_version: '2024.02',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.01'
              },
              imported_at: '2024-02-15T08:00:00.000Z',
              verified_at: '2024-02-15T08:10:00.000Z',
              signature: 'sig-new'
            },
            {
              id: 'manifest-older',
              version: '2024.02',
              manifest: {
                feed_version: '2024.02',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.00'
              },
              imported_at: '2024-02-01T08:00:00.000Z',
              verified_at: '2024-02-01T08:05:00.000Z',
              signature: 'sig-old'
            }
          ]
        };
      }

      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2024.02' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        manifestQuerySql = sql;
        if (sql.includes('ORDER BY imported_at DESC, id DESC')) {
          return {
            rows: [
              {
                manifest: {
                  feed_version: '2024.02',
                  packages: [],
                  vulnerabilities: [],
                  minimum_downgrade_version: '2024.01'
                }
              }
            ]
          };
        }

        return {
          rows: [
            {
              manifest: {
                feed_version: '2024.02',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.00'
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'GET',
      url: `/v1/feeds?tenant_id=${TEST_TENANT_ID}`,
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.active_version).toBe('2024.02');
    expect(body.active_minimum_downgrade_version).toBe('2024.01');
    expect(body.data?.[0]).toMatchObject({ minimum_downgrade_version: '2024.01' });
    expect(manifestQuerySql).toContain('ORDER BY imported_at DESC, id DESC');
  });

  it('activates a feed manifest using the stored version', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: {} }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return { rows: [] };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.02',
              verified_at: '2024-02-01T00:30:00.000Z',
              signature: 'sig-verified',
              manifest: {
                feed_version: '2024.02',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.00'
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/activate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID,
        version: '2024.02'
      }
    });

    expect(response.statusCode).toBe(204);
    expect(feedCounter).toHaveBeenCalledWith({ action: 'activate' });

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall?.[1]).toEqual([TEST_TENANT_ID, '2024.02', '2024.00']);

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    const auditPayload = auditCall?.[1]?.[6] as Record<string, unknown> | undefined;
    expect(auditPayload).toMatchObject({
      manifest_id: TEST_MANIFEST_ID,
      version: '2024.02',
      manifest_signature_present: true,
      manifest_signature_verified: true
    });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.activate',
        manifest_id: TEST_MANIFEST_ID,
        version: '2024.02',
        actor: expect.stringMatching(/^api_key:/u),
        result: 'success',
        metadata: expect.objectContaining({
          signature_present: true,
          signature_verified: true,
          minimum_downgrade_version: '2024.00'
        })
      })
    );
  });

  it('blocks activation when manifest signature has not been verified', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: {} }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return { rows: [] };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.02',
              verified_at: null,
              signature: 'sig-present',
              manifest: { feed_version: '2024.02', packages: [], vulnerabilities: [] }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/activate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.activate',
        manifest_id: TEST_MANIFEST_ID,
        result: 'blocked',
        metadata: expect.objectContaining({
          reason: 'signature_not_verified',
          signature_present: true,
          signature_verified: false
        })
      })
    );

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall).toBeUndefined();

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    expect(auditCall?.[1]?.[5]).toBe('feed.activate_blocked');
  });

  it('rejects activation attempts when the provided version mismatches the manifest', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: {} }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return { rows: [] };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.01',
              verified_at: null,
              signature: null,
              manifest: {
                feed_version: '2024.01',
                packages: [],
                vulnerabilities: []
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/activate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID,
        version: '2024.05'
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'validation_error' } });

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall).toBeUndefined();

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.activate',
        manifest_id: TEST_MANIFEST_ID,
        result: 'failure',
        metadata: expect.objectContaining({ reason: 'version_mismatch' })
      })
    );
  });

  it('blocks activation when manifest omits minimum downgrade floor', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2024.07', minimum_downgrade_version: '2024.04' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return { rows: [] };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.08',
              verified_at: '2024-08-01T08:00:00.000Z',
              signature: 'sig-verified',
              manifest: { feed_version: '2024.08', packages: [], vulnerabilities: [] }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/activate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });
    expect(feedCounter).not.toHaveBeenCalled();

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    expect(auditCall?.[1]?.[5]).toBe('feed.activate_blocked');
    const auditPayload = auditCall?.[1]?.[6] as Record<string, unknown> | undefined;
    expect(auditPayload).toMatchObject({
      manifest_id: TEST_MANIFEST_ID,
      version: '2024.08',
      reason: 'minimum_downgrade_version_missing'
    });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.activate',
        manifest_id: TEST_MANIFEST_ID,
        result: 'blocked',
        metadata: expect.objectContaining({
          reason: 'minimum_downgrade_version_missing',
          active_minimum_downgrade_version: '2024.04'
        })
      })
    );
  });

  it('blocks activation when the target version is older than the active feed', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2024.05' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return {
          rows: [
            {
              manifest: {
                feed_version: '2024.05',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.02'
              }
            }
          ]
        };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.03',
              verified_at: '2024-01-01T00:00:00.000Z',
              signature: 'mock-signature',
              manifest: {
                feed_version: '2024.03',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.00'
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/activate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.activate',
        manifest_id: TEST_MANIFEST_ID,
        result: 'blocked',
        metadata: expect.objectContaining({
          reason: 'older_than_active_version',
          active_version: '2024.05',
          minimum_downgrade_version: '2024.02'
        })
      })
    );

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall).toBeUndefined();
  });

  it('blocks activation when manifest lowers the minimum downgrade floor', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2024.09', minimum_downgrade_version: '2024.06' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return {
          rows: [
            {
              manifest: {
                feed_version: '2024.09',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.06'
              }
            }
          ]
        };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.10',
              verified_at: '2024-10-01T08:00:00.000Z',
              signature: 'sig-verified',
              manifest: {
                feed_version: '2024.10',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.05'
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/activate',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID,
        version: '2024.10'
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.activate',
        manifest_id: TEST_MANIFEST_ID,
        result: 'blocked',
        metadata: expect.objectContaining({
          reason: 'minimum_downgrade_version_lower_than_floor',
          target_minimum_downgrade_version: '2024.05',
          active_minimum_downgrade_version: '2024.06'
        })
      })
    );

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    expect(auditCall?.[1]?.[5]).toBe('feed.activate_blocked');
    const auditPayload = auditCall?.[1]?.[6] as Record<string, unknown> | undefined;
    expect(auditPayload).toMatchObject({
      manifest_id: TEST_MANIFEST_ID,
      reason: 'minimum_downgrade_version_lower_than_floor',
      target_minimum_downgrade_version: '2024.05',
      active_minimum_downgrade_version: '2024.06'
    });

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall).toBeUndefined();
    expect(feedCounter).not.toHaveBeenCalled();
  });

  it('rolls back to a previous version using manifest metadata', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2023.12' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return {
          rows: [
            {
              manifest: {
                feed_version: '2023.12',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2023.01'
              }
            }
          ]
        };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2023.12',
              verified_at: '2024-01-01T00:00:00.000Z',
              signature: 'mock',
              manifest: {
                feed_version: '2023.12',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2023.00'
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/rollback',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID
      }
    });

    expect(response.statusCode).toBe(204);
    expect(feedCounter).toHaveBeenCalledWith({ action: 'rollback' });

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall?.[1]).toEqual([TEST_TENANT_ID, '2023.12', '2023.00']);

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    const auditPayload = auditCall?.[1]?.[6] as Record<string, unknown> | undefined;
    expect(auditPayload).toMatchObject({
      manifest_id: TEST_MANIFEST_ID,
      version: '2023.12',
      manifest_signature_present: true,
      manifest_signature_verified: true
    });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.rollback',
        manifest_id: TEST_MANIFEST_ID,
        version: '2023.12',
        actor: expect.stringMatching(/^api_key:/u),
        result: 'success',
        metadata: expect.objectContaining({
          signature_present: true,
          signature_verified: true,
          minimum_downgrade_version: '2023.00',
          active_version: '2023.12'
        })
      })
    );
  });

  it('blocks rollback when manifest signature has not been verified', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2023.12' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return { rows: [{ manifest: { feed_version: '2023.12', packages: [], vulnerabilities: [] } }] };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2023.10',
              verified_at: null,
              signature: 'sig-present',
              manifest: { feed_version: '2023.10', packages: [], vulnerabilities: [] }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/rollback',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID,
        version: '2023.10'
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.rollback',
        manifest_id: TEST_MANIFEST_ID,
        result: 'blocked',
        metadata: expect.objectContaining({
          reason: 'signature_not_verified',
          signature_present: true,
          signature_verified: false
        })
      })
    );

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall).toBeUndefined();

    const auditCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO audit_log_events')
    );
    expect(auditCall?.[1]?.[5]).toBe('feed.rollback_blocked');
  });

  it('blocks rollback attempts that violate minimum_downgrade_version', async () => {
    db.query.mockImplementation(async (sql: string) => {
      if (sql.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: { active_feed_version: '2024.05' } }] };
      }

      if (sql.includes('FROM feed_manifests') && sql.includes('WHERE tenant_id = $1 AND version = $2')) {
        return {
          rows: [
            {
              manifest: {
                feed_version: '2024.05',
                packages: [],
                vulnerabilities: [],
                minimum_downgrade_version: '2024.03'
              }
            }
          ]
        };
      }

      if (
        sql.includes('SELECT id, version, verified_at, signature, manifest') &&
        sql.includes('WHERE id = $1')
      ) {
        return {
          rows: [
            {
              id: TEST_MANIFEST_ID,
              version: '2024.02',
              verified_at: '2024-01-02T00:00:00.000Z',
              signature: 'mock-signature',
              manifest: {
                feed_version: '2024.02',
                packages: [],
                vulnerabilities: []
              }
            }
          ]
        };
      }

      return { rows: [] };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/feeds/rollback',
      headers: authHeaders,
      payload: {
        tenant_id: TEST_TENANT_ID,
        manifest_id: TEST_MANIFEST_ID
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'conflict' } });

    expect(recordUpdateLogEntryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'feed.rollback',
        manifest_id: TEST_MANIFEST_ID,
        result: 'blocked',
        metadata: expect.objectContaining({
          reason: 'below_minimum_downgrade_version',
          minimum_downgrade_version: '2024.03',
          active_version: '2024.05'
        })
      })
    );

    const updateCall = db.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('jsonb_set(metadata::jsonb,')
    );
    expect(updateCall).toBeUndefined();
  });
});
