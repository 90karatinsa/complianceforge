// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';
import { Writable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import * as licenseManager from '../scripts/license-manager.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createEd25519PublicKey, createLicenseStatus, TEST_LICENSE_PUBLIC_KEY } from './helpers/license.ts';

const ALTERNATE_LICENSE_PUBLIC_KEY = createEd25519PublicKey(1);

const TEST_VERSION = '0.0.0-test';
const TEST_TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const ORIGINAL_API_KEYS_SALT = process.env.API_KEYS_SALT;

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
    },
    Registry: MockRegistry,
    Counter: MockMetric,
    Gauge: MockMetric,
    Histogram: MockMetric,
    collectDefaultMetrics: () => {}
  } satisfies Metrics & {
    Registry: typeof MockRegistry;
    Counter: typeof MockMetric;
    Gauge: typeof MockMetric;
    Histogram: typeof MockMetric;
    collectDefaultMetrics: () => void;
  };
});

describe('API key salt configuration', () => {
  afterEach(() => {
    if (ORIGINAL_API_KEYS_SALT === undefined) {
      delete process.env.API_KEYS_SALT;
    } else {
      process.env.API_KEYS_SALT = ORIGINAL_API_KEYS_SALT;
    }
  });

  function createBaseOptions(overrides: Partial<Parameters<typeof buildServer>[0]> = {}) {
    const baseOptions = {
      version: TEST_VERSION,
      db: createDbMock(),
      queue: createQueueMock(),
      redis: createRedisMock(),
      metrics: createMetricsStub(),
      lookupApiKey: vi.fn().mockResolvedValue(null),
      licensePublicKey: TEST_LICENSE_PUBLIC_KEY,
      licenseStatusProvider: vi.fn().mockResolvedValue(createLicenseStatus())
    } satisfies Parameters<typeof buildServer>[0];

    return { ...baseOptions, ...overrides } satisfies Parameters<typeof buildServer>[0];
  }

  it('rejects when the provided salt is empty', async () => {
    await expect(
      buildServer({
        ...createBaseOptions(),
        apiKeySalt: '   '
      })
    ).rejects.toThrow(/API_KEYS_SALT must be configured/);
  });

  it('rejects when no salt is configured anywhere', async () => {
    delete process.env.API_KEYS_SALT;

    await expect(buildServer(createBaseOptions())).rejects.toThrow(
      /API_KEYS_SALT must be configured/
    );
  });
});

describe('API authentication', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: RedisConnection;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;
  let lookupApiKey: ReturnType<typeof createAuthMocks>['lookupApiKey'];
  let licenseStatusProvider: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    db = createDbMock();
    db.query.mockResolvedValue({
      rows: [
        {
          id: 'project-1',
          tenant_id: TEST_TENANT_ID,
          name: 'Example Project'
        }
      ]
    });
    queue = createQueueMock();
    redis = createRedisMock();
    metrics = createMetricsStub();
    const auth = createAuthMocks(TEST_TENANT_ID);
    authHeaders = auth.headers;
    lookupApiKey = auth.lookupApiKey;
      licenseStatusProvider = vi.fn().mockResolvedValue(createLicenseStatus());

    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licensePublicKey: TEST_LICENSE_PUBLIC_KEY,
      licenseStatusProvider
    });

    await app.ready();
  });

  afterEach(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it('rejects requests without a bearer token', async () => {
    const response = await app.inject({ method: 'GET', url: '/v1/projects', query: { tenant_id: TEST_TENANT_ID } });
    expect(response.statusCode).toBe(401);
    const body = response.json<{
      error: { code: string; message: string; request_id: string };
    }>();
    expect(body.error.code).toBe('unauthorized');
    expect(body.error.message).toBe('Missing or invalid API key.');
    expect(body.error.request_id).toEqual(expect.any(String));
    expect(db.query).not.toHaveBeenCalled();
  });

  it('rejects requests with an invalid token', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID },
      headers: { authorization: 'Bearer invalid-token' }
    });

    expect(response.statusCode).toBe(401);
    const body = response.json<{ error?: { code?: string } }>();
    expect(body.error?.code).toBe('unauthorized');
  });

  it('allows requests with a valid token and scopes queries to the tenant', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '1', page_size: '5' },
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(db.query).toHaveBeenCalledWith(
      expect.stringContaining('WHERE tenant_id = $1'),
      [TEST_TENANT_ID, 5, 0]
    );
    const body = response.json<{
      data?: Array<{ id: string; tenant_id: string; name: string }>;
    }>();
    expect(body?.data?.[0]?.tenant_id).toBe(TEST_TENANT_ID);
  });

  it('caches successful API key lookups within the TTL window', async () => {
    vi.useFakeTimers();
    const auth = createAuthMocks(TEST_TENANT_ID);
    const cachedLookup = vi.fn(auth.lookupApiKey);

    await app.close();
    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: cachedLookup,
      licensePublicKey: TEST_LICENSE_PUBLIC_KEY,
      licenseStatusProvider
    });

    await app.ready();

    const request = {
      method: 'GET' as const,
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '1', page_size: '5' },
      headers: auth.headers
    };

    await app.inject(request);
    await app.inject(request);

    expect(cachedLookup).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(6_000);
    await app.inject(request);
    expect(cachedLookup).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

  it('caches missing API keys to avoid repeated lookups', async () => {
    vi.useFakeTimers();
    const missingLookup = vi.fn().mockResolvedValue(null);

    await app.close();
    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: missingLookup,
      licensePublicKey: TEST_LICENSE_PUBLIC_KEY,
      licenseStatusProvider
    });

    await app.ready();

    const invalidRequest = {
      method: 'GET' as const,
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID },
      headers: { authorization: 'Bearer invalid-token' }
    };

    await app.inject(invalidRequest);
    await app.inject(invalidRequest);

    expect(missingLookup).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it('redacts sensitive headers from structured logs', async () => {
    const chunks: string[] = [];
    const destination = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(chunk.toString());
        callback();
      }
    });

    const loggingApp = await buildServer({
      version: TEST_VERSION,
      db: createDbMock(),
      queue: createQueueMock(),
      redis: createRedisMock(),
      metrics: createMetricsStub(),
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: vi.fn().mockResolvedValue(null),
      licensePublicKey: TEST_LICENSE_PUBLIC_KEY,
      licenseStatusProvider: vi.fn().mockResolvedValue(createLicenseStatus()),
      logDestination: destination
    });

    try {
      await loggingApp.ready();
      loggingApp.log.info(
        {
          req: {
            headers: {
              authorization: 'Bearer secret-token',
              'idempotency-key': 'request-123',
              cookie: 'session=abc',
              'x-api-key': 'api-key-secret'
            }
          },
          res: {
            headers: {
              'set-cookie': 'session=abc'
            }
          }
        },
        'sensitive headers should be removed'
      );

      await new Promise((resolve) => {
        setImmediate(resolve);
      });

      const serialized = chunks.join('');
      expect(serialized).not.toBe('');
      const record = JSON.parse(serialized.split('\n').filter(Boolean).pop() ?? '{}');

      expect(record.req?.headers?.authorization).toBeUndefined();
      expect(record.req?.headers?.['idempotency-key']).toBeUndefined();
      expect(record.req?.headers?.cookie).toBeUndefined();
      expect(record.req?.headers?.['x-api-key']).toBeUndefined();
      expect(record.res?.headers?.['set-cookie']).toBeUndefined();

      const output = JSON.stringify(record);
      expect(output).not.toContain('secret-token');
      expect(output).not.toContain('request-123');
      expect(output).not.toContain('session=abc');
      expect(output).not.toContain('api-key-secret');
    } finally {
      await loggingApp.close();
    }
  });
});

describe('license enforcement', () => {
  function createServerOptions(overrides: Partial<LicenseStatusResult>) {
    const licenseStatusProvider = vi.fn().mockResolvedValue(createLicenseStatus(overrides));

    const options = {
      version: TEST_VERSION,
      db: createDbMock(),
      queue: createQueueMock(),
      redis: createRedisMock(),
      metrics: createMetricsStub(),
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: vi.fn().mockResolvedValue(null),
      licenseStatusProvider
    } satisfies Parameters<typeof buildServer>[0];

    return { options, licenseStatusProvider } as const;
  }

  it('rejects startup when the license is revoked', async () => {
    const { options, licenseStatusProvider } = createServerOptions({ status: 'revoked' });

    await expect(buildServer(options)).rejects.toThrow(/revoked/i);
    expect(licenseStatusProvider).toHaveBeenCalledTimes(1);
  });

  it('rejects startup when the license lacks scan entitlement', async () => {
    const { options, licenseStatusProvider } = createServerOptions({ features: [] });

    await expect(buildServer(options)).rejects.toThrow(/scan:execute/i);
    expect(licenseStatusProvider).toHaveBeenCalledTimes(1);
  });
});
  it('passes the resolved license public key to the default license status provider', async () => {
    const getLicenseStatusSpy = vi
      .spyOn(licenseManager, 'getLicenseStatus')
      .mockResolvedValue(createLicenseStatus());

    const server = await buildServer({
      version: TEST_VERSION,
      db: createDbMock(),
      queue: createQueueMock(),
      redis: createRedisMock(),
      metrics: createMetricsStub(),
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: vi.fn().mockResolvedValue(null),
      licensePublicKey: ALTERNATE_LICENSE_PUBLIC_KEY
    });

    expect(getLicenseStatusSpy).toHaveBeenCalledWith(
      expect.objectContaining({ publicKey: ALTERNATE_LICENSE_PUBLIC_KEY })
    );

    await server.close();
    getLicenseStatusSpy.mockRestore();
  });

function createDbMock(): { query: ReturnType<typeof vi.fn> } & Database {
  return { query: vi.fn().mockResolvedValue({ rows: [] }) } as {
    query: ReturnType<typeof vi.fn>;
  } & Database;
}

function createQueueMock(): { add: ReturnType<typeof vi.fn> } & JobQueue {
  return { add: vi.fn().mockResolvedValue(undefined) } as { add: ReturnType<typeof vi.fn> } & JobQueue;
}

function createRedisMock(): RedisConnection {
  return { ping: vi.fn().mockResolvedValue('PONG') } satisfies RedisConnection;
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

