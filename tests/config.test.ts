// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { TEST_LICENSE_PUBLIC_KEY } from './helpers/license.ts';

const secretsModule = vi.hoisted(() => {
  const sendMock = vi.fn<Promise<{ SecretString?: string; SecretBinary?: Uint8Array }>, [unknown]>();

  class SecretsManagerClientMock {
    public send = sendMock;
  }

  class GetSecretValueCommandMock {
    public readonly input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  }

  return { sendMock, SecretsManagerClientMock, GetSecretValueCommandMock } as const;
});

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: secretsModule.SecretsManagerClientMock,
  GetSecretValueCommand: secretsModule.GetSecretValueCommandMock
}));

import {
  __testResetApiSecretCache,
  __testSecretCacheTtlMs,
  loadApiConfig
} from '../api/src/server.ts';

type TestEnv = Record<string, string>;

const BASE_ENV: TestEnv = {
  DATABASE_URL: 'postgres://localhost:5432/app',
  REDIS_URL: 'redis://localhost:6379',
  API_KEYS_SALT: 'test-salt',
  LICENSE_PUBLIC_KEY: TEST_LICENSE_PUBLIC_KEY,
  MAX_CONCURRENCY: '4',
  SCAN_TIMEOUT_S: '900',
  WEBHOOK_MAX_RETRY: '5',
  PROMETHEUS_PORT: '9464',
  SCAN_QUEUE_NAME: 'scan-jobs',
  WEBHOOK_SECRET_KEY: Buffer.alloc(32, 0x5a).toString('base64')
};

const secretsSendMock = secretsModule.sendMock;

afterEach(() => {
  vi.useRealTimers();
  secretsSendMock.mockReset();
  __testResetApiSecretCache();
});

vi.mock('prom-client', () => {
  class MockMetric {
    inc() {}
    set() {}
    labels() {
      return this;
    }
    startTimer() {
      return () => {};
    }
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

describe('loadApiConfig', () => {
  it('parses environment variables into runtime config', async () => {
    const config = await loadApiConfig(BASE_ENV);

    expect(config).toMatchObject({
      databaseUrl: BASE_ENV.DATABASE_URL,
      redisUrl: BASE_ENV.REDIS_URL,
      apiKeySalt: BASE_ENV.API_KEYS_SALT,
      licensePublicKey: TEST_LICENSE_PUBLIC_KEY,
      scanQueueName: BASE_ENV.SCAN_QUEUE_NAME,
      maxConcurrency: 4,
      scanTimeoutSeconds: 900,
      webhookMaxRetry: 5,
      prometheusPort: 9464,
      telemetryEnabled: false
    });
    expect(Buffer.isBuffer(config.webhookSecretKey)).toBe(true);
    expect(config.webhookSecretKey.length).toBe(32);
  });

  it('throws a descriptive error when a required field is missing', async () => {
    const brokenEnv: TestEnv = {
      ...BASE_ENV
    };
    delete brokenEnv.REDIS_URL;

    await expect(loadApiConfig(brokenEnv)).rejects.toThrow(/REDIS_URL must be configured/i);
  });

  it('rejects invalid numeric values', async () => {
    const invalidEnv: TestEnv = {
      ...BASE_ENV,
      MAX_CONCURRENCY: '0'
    };

    await expect(loadApiConfig(invalidEnv)).rejects.toThrow(/MAX_CONCURRENCY must be a positive integer/i);
  });

  it('parses telemetry flags and enforces boolean semantics', async () => {
    const enabledEnv: TestEnv = {
      ...BASE_ENV,
      TELEMETRY_ENABLED: 'true'
    };

    expect((await loadApiConfig(enabledEnv)).telemetryEnabled).toBe(true);

    const invalidEnv: TestEnv = {
      ...BASE_ENV,
      TELEMETRY_ENABLED: 'maybe'
    };

    await expect(loadApiConfig(invalidEnv)).rejects.toThrow(/Boolean environment flags must be true or false/i);
  });

  it('disables telemetry when explicitly set to false', async () => {
    const config = await loadApiConfig({
      ...BASE_ENV,
      TELEMETRY_ENABLED: 'false'
    });

    expect(config.telemetryEnabled).toBe(false);
  });

  it('resolves Secrets Manager URIs containing raw string secrets', async () => {
    secretsSendMock.mockResolvedValueOnce({ SecretString: 'postgres://aws-host:5432/app' });

    const config = await loadApiConfig({
      ...BASE_ENV,
      DATABASE_URL: 'secretsmanager://prod/app-db'
    });

    expect(config.databaseUrl).toBe('postgres://aws-host:5432/app');
    expect(secretsSendMock).toHaveBeenCalledTimes(1);
    const call = secretsSendMock.mock.calls[0]?.[0] as { input?: { SecretId?: string } } | undefined;
    expect(call?.input?.SecretId).toBe('prod/app-db');
  });

  it('extracts nested properties from JSON secrets when requested', async () => {
    secretsSendMock.mockResolvedValueOnce({ SecretString: JSON.stringify({ salt: 'derived-salt' }) });

    const config = await loadApiConfig({
      ...BASE_ENV,
      API_KEYS_SALT: 'secretsmanager://prod/api-key#salt'
    });

    expect(config.apiKeySalt).toBe('derived-salt');
  });

  it('throws a descriptive error when Secrets Manager resolution fails', async () => {
    secretsSendMock.mockRejectedValueOnce(new Error('AccessDeniedException'));

    await expect(
      loadApiConfig({
        ...BASE_ENV,
        DATABASE_URL: 'secretsmanager://prod/app-db'
      })
    ).rejects.toThrow(/Failed to resolve DATABASE_URL from AWS Secrets Manager/i);
  });

  it('rejects license public keys that are not base64url encoded', async () => {
    const invalidEnv: TestEnv = {
      ...BASE_ENV,
      LICENSE_PUBLIC_KEY: 'not-a valid key'
    };

    await expect(loadApiConfig(invalidEnv)).rejects.toThrow(/LICENSE_PUBLIC_KEY must be a base64url-encoded DER public key string/i);
  });

  it('rejects license public keys with invalid length', async () => {
    const invalidEnv: TestEnv = {
      ...BASE_ENV,
      LICENSE_PUBLIC_KEY: Buffer.from([0x30, 0x01]).toString('base64url')
    };

    await expect(loadApiConfig(invalidEnv)).rejects.toThrow(/LICENSE_PUBLIC_KEY must decode to a 44 byte Ed25519 public key/i);
  });

  it('rejects webhook secret keys that are not base64 encoded 32-byte values', async () => {
    const invalidEnv: TestEnv = {
      ...BASE_ENV,
      WEBHOOK_SECRET_KEY: 'short'
    };

    await expect(loadApiConfig(invalidEnv)).rejects.toThrow(/WEBHOOK_SECRET_KEY must be a base64-encoded 32-byte key/i);
  });

  it('reuses cached Secrets Manager values until the TTL expires', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));

    secretsSendMock.mockResolvedValueOnce({ SecretString: 'postgres://aws-host:5432/app' });

    const secretEnv: TestEnv = {
      ...BASE_ENV,
      DATABASE_URL: 'secretsmanager://prod/app-db'
    };

    const first = await loadApiConfig(secretEnv);
    expect(first.databaseUrl).toBe('postgres://aws-host:5432/app');
    expect(secretsSendMock).toHaveBeenCalledTimes(1);

    const second = await loadApiConfig(secretEnv);
    expect(second.databaseUrl).toBe('postgres://aws-host:5432/app');
    expect(secretsSendMock).toHaveBeenCalledTimes(1);
  });

  it('refetches Secrets Manager values after the TTL expires', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));

    secretsSendMock.mockResolvedValueOnce({ SecretString: 'postgres://aws-host:5432/app' });

    const secretEnv: TestEnv = {
      ...BASE_ENV,
      DATABASE_URL: 'secretsmanager://prod/app-db'
    };

    const first = await loadApiConfig(secretEnv);
    expect(first.databaseUrl).toBe('postgres://aws-host:5432/app');
    expect(secretsSendMock).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(__testSecretCacheTtlMs - 1);
    const stillCached = await loadApiConfig(secretEnv);
    expect(stillCached.databaseUrl).toBe('postgres://aws-host:5432/app');
    expect(secretsSendMock).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(1);
    secretsSendMock.mockResolvedValueOnce({ SecretString: 'postgres://aws-rotated:5432/app' });

    const refreshed = await loadApiConfig(secretEnv);
    expect(refreshed.databaseUrl).toBe('postgres://aws-rotated:5432/app');
    expect(secretsSendMock).toHaveBeenCalledTimes(2);
  });
});
