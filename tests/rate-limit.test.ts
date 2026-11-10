// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  RATE_LIMITER_DEBUG_STORE_SIZE,
  buildServer,
  createRateLimiter,
  type Database,
  type JobQueue,
  type RedisConnection
} from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createAuthMocks, TEST_API_KEY_ID, TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';

const TEST_VERSION = '0.0.0-test';
const TEST_TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

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

function createRedisStub() {
  const store = new Map<string, RateLimitStoreEntry>();

  function getEntry(key: string): RateLimitStoreEntry | null {
    const existing = store.get(key);

    if (!existing) {
      return null;
    }

    if (existing.expiresAt !== null && existing.expiresAt <= Date.now()) {
      store.delete(key);
      return null;
    }

    return existing;
  }

  return {
    ping: vi.fn().mockResolvedValue('PONG'),
    incrby: vi.fn((key: string, increment: number) => {
      const current = getEntry(key) ?? { value: 0, expiresAt: null };
      current.value += increment;
      store.set(key, current);
      return Promise.resolve(current.value);
    }),
    ttl: vi.fn((key: string) => {
      const current = getEntry(key);

      if (!current) {
        return Promise.resolve(-2);
      }

      if (current.expiresAt === null) {
        return Promise.resolve(-1);
      }

      const diff = current.expiresAt - Date.now();
      return Promise.resolve(diff <= 0 ? 0 : Math.ceil(diff / 1000));
    }),
    expire: vi.fn((key: string, seconds: number) => {
      const current = getEntry(key);

      if (!current) {
        return Promise.resolve(0);
      }

      current.expiresAt = Date.now() + seconds * 1000;
      store.set(key, current);
      return Promise.resolve(1);
    }),
    setCount(key: string, value: number, ttlSeconds: number | null) {
      const expiresAt = ttlSeconds === null ? null : Date.now() + ttlSeconds * 1000;
      store.set(key, { value, expiresAt });
    }
  } satisfies RedisConnection & {
    incrby(key: string, increment: number): Promise<number>;
    ttl(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
    setCount(key: string, value: number, ttlSeconds: number | null): void;
  };
}

describe('API rate limiting', () => {
  let db: { query: ReturnType<typeof vi.fn> } & Database;
  let queue: { add: ReturnType<typeof vi.fn> } & JobQueue;
  let redis: ReturnType<typeof createRedisStub>;
  let metrics: Metrics;
  let app: Awaited<ReturnType<typeof buildServer>>;
  let authHeaders: Record<string, string>;
  let lookupApiKey: ReturnType<typeof createAuthMocks>['lookupApiKey'];

  beforeEach(async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z'));

    db = createDbMock();
    queue = createQueueMock();
    redis = createRedisStub();
    metrics = createMetricsStub();
    const auth = createAuthMocks(TEST_TENANT_ID);
    authHeaders = auth.headers;
    lookupApiKey = vi.fn(auth.lookupApiKey);

    app = await buildServer({
      version: TEST_VERSION,
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey,
      licenseStatusProvider: createLicenseStatusProvider()
    });
  });

  afterEach(async () => {
    vi.useRealTimers();
    if (app) {
      await app.close();
    }

    vi.restoreAllMocks();
  });

  it('allows requests within minute and daily limits and sets headers', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '1', page_size: '5' },
      headers: authHeaders
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['x-ratelimit-limit-minute']).toBe('30');
    expect(response.headers['x-ratelimit-remaining-minute']).toBe('29');
    expect(response.headers['x-ratelimit-reset-minute']).toBe('60');
    expect(response.headers['x-ratelimit-limit-day']).toBe('10000');
    expect(response.headers['x-ratelimit-remaining-day']).toBe('9999');
    expect(lookupApiKey).toHaveBeenCalledTimes(1);
  });

  it('enforces the per-minute limit and returns retry metadata', async () => {
    for (let index = 0; index < 30; index += 1) {
      const allowed = await app.inject({
        method: 'GET',
        url: '/v1/projects',
        query: { tenant_id: TEST_TENANT_ID, page: String(index + 1), page_size: '5' },
        headers: authHeaders
      });

      expect(allowed.statusCode).toBe(200);
    }

    const blocked = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '31', page_size: '5' },
      headers: authHeaders
    });

    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers['retry-after']).toBe('60');
    expect(lookupApiKey).toHaveBeenCalledTimes(1);
    expect(blocked.headers['x-ratelimit-remaining-minute']).toBe('0');
    const blockedBody = blocked.json<{
      error: {
        code: string;
        message: string;
        request_id: string;
        meta: { scope: string; limit: number; remaining: number; reset_seconds: number };
      };
    }>();
    expect(blockedBody.error.code).toBe('rate_limit_exceeded');
    expect(blockedBody.error.meta).toEqual({
      scope: 'minute',
      limit: 30,
      remaining: 0,
      reset_seconds: 60
    });
    expect(blockedBody.error.request_id).toEqual(expect.any(String));
  });

  it('resets the per-minute limit window after expiry and enforces daily cap', async () => {
    for (let index = 0; index < 30; index += 1) {
      const allowed = await app.inject({
        method: 'GET',
        url: '/v1/projects',
        query: { tenant_id: TEST_TENANT_ID, page: String(index + 1), page_size: '5' },
        headers: authHeaders
      });

      expect(allowed.statusCode).toBe(200);
    }

    const firstBlocked = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '31', page_size: '5' },
      headers: authHeaders
    });

    expect(firstBlocked.statusCode).toBe(429);

    const minuteKey = `rate_limit:minute:${TEST_API_KEY_ID}`;
    const dayKey = `rate_limit:day:${TEST_API_KEY_ID}`;
    redis.setCount(dayKey, 9_999, 86_400);

    vi.advanceTimersByTime(61_000);

    const postReset = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '33', page_size: '5' },
      headers: authHeaders
    });

    expect(postReset.statusCode).toBe(200);
    expect(postReset.headers['x-ratelimit-remaining-minute']).toBe('29');

    redis.setCount(minuteKey, 0, 60);
    redis.setCount(dayKey, 10_000, 86_400);

    const dailyBlocked = await app.inject({
      method: 'GET',
      url: '/v1/projects',
      query: { tenant_id: TEST_TENANT_ID, page: '34', page_size: '5' },
      headers: authHeaders
    });

    expect(dailyBlocked.statusCode).toBe(429);
    expect(dailyBlocked.headers['retry-after']).toBe('86400');
    const dailyBlockedBody = dailyBlocked.json<{
      error: {
        code: string;
        message: string;
        request_id: string;
        meta: { scope: string; limit: number; remaining: number; reset_seconds: number };
      };
    }>();
    expect(dailyBlockedBody.error.code).toBe('rate_limit_exceeded');
    expect(dailyBlockedBody.error.meta).toEqual({
      scope: 'day',
      limit: 10000,
      remaining: 0,
      reset_seconds: 86400
    });
    expect(dailyBlockedBody.error.request_id).toEqual(expect.any(String));
  });

  it('purges expired in-memory windows to avoid unbounded growth', async () => {
    const inMemoryRedis = { ping: vi.fn().mockResolvedValue('PONG') } satisfies RedisConnection;
    const rateLimiter = createRateLimiter(inMemoryRedis);
    const getStoreSize = rateLimiter[RATE_LIMITER_DEBUG_STORE_SIZE];

    expect(getStoreSize).toBeDefined();

    const start = new Date('2024-01-01T00:00:00.000Z');

    for (let index = 0; index < 200; index += 1) {
      await rateLimiter(`key-${index}`, start);
    }

    expect(getStoreSize?.()).toBeGreaterThanOrEqual(200);

    const future = new Date(start.getTime() + 86_400_000 + 5_000);
    await rateLimiter('key-final', future);

    expect(getStoreSize?.()).toBeLessThanOrEqual(2);
  });
});

function createDbMock(): { query: ReturnType<typeof vi.fn> } & Database {
  return { query: vi.fn().mockResolvedValue({ rows: [] }) } as {
    query: ReturnType<typeof vi.fn>;
  } & Database;
}

function createQueueMock(): { add: ReturnType<typeof vi.fn> } & JobQueue {
  return { add: vi.fn().mockResolvedValue(undefined) } as {
    add: ReturnType<typeof vi.fn>;
  } & JobQueue;
}
