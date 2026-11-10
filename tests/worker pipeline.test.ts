// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';
import { createHmac, createCipheriv } from 'node:crypto';
import { mkdtemp, writeFile, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { OsvVulnerability } from '../worker/src/scanners.ts';
import type Redis from 'ioredis';
import * as licenseManager from '../scripts/license-manager.ts';
import { TEST_LICENSE_PUBLIC_KEY, createEd25519PublicKey } from './helpers/license.ts';

const DIFFERENT_LICENSE_PUBLIC_KEY = createEd25519PublicKey(2);
const RESOLVED_SECRET_LICENSE_PUBLIC_KEY = createEd25519PublicKey(3);
const TEST_WEBHOOK_SECRET_KEY = Buffer.alloc(32, 0x42);

const pgModule = vi.hoisted(() => {
  const poolQueryMock = vi.fn<Promise<{ rows: unknown[] }>, [string, unknown[] | undefined]>(() =>
    Promise.resolve({ rows: [] })
  );
  const connectMock = vi.fn<Promise<{ query?: typeof poolQueryMock; release?: (error?: unknown) => void }>, []>();

  class PoolMock {
    public query = poolQueryMock;
    public connect = connectMock;

    constructor(_: unknown) {
      // noop
    }
  }

  return { poolQueryMock, connectMock, PoolMock } as const;
});

vi.mock('pg', () => ({
  Pool: pgModule.PoolMock
}));

const bullModule = vi.hoisted(() => {
  const WorkerMock = vi.fn(
    () => ({
      on: vi.fn(),
      close: vi.fn(() => Promise.resolve()),
      pause: vi.fn(() => Promise.resolve()),
      resume: vi.fn(() => Promise.resolve())
    })
  );

  return { WorkerMock } as const;
});

vi.mock('bullmq', () => ({
  Worker: bullModule.WorkerMock
}));

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

vi.mock('keytar', () => ({
  default: {
    setPassword: vi.fn(() => Promise.resolve()),
    getPassword: vi.fn(() => Promise.resolve(null)),
    deletePassword: vi.fn(() => Promise.resolve(true))
  }
}));

const dnsMock = vi.hoisted(() => ({
  lookupMock: vi.fn<Promise<Array<{ address: string; family: number }>>, [string, { all: true }]>(() =>
    Promise.resolve([{ address: '203.0.113.1', family: 4 }])
  )
}));

const agentModule = vi.hoisted(() => {
  const instances: Array<{
    options: { connect?: { lookup?: (typeof dnsMock.lookupMock) } };
    dispatch: ReturnType<typeof vi.fn>;
    close: ReturnType<typeof vi.fn>;
    destroy: ReturnType<typeof vi.fn>;
  }> = [];

  const Agent = vi.fn((options: { connect?: { lookup?: (typeof dnsMock.lookupMock) } }) => {
    const instance = {
      options,
      dispatch: vi.fn(),
      close: vi.fn(() => Promise.resolve()),
      destroy: vi.fn(() => Promise.resolve())
    };
    instances.push(instance);
    return instance;
  });

  return { Agent, instances };
});

vi.mock('prom-client', () => {
  class MockMetric {
    startTimer() {
      return () => {};
    }

    labels() {
      return this;
    }

    set() {
      // noop
    }

    inc() {
      // noop
    }

    reset() {
      // noop
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

vi.mock('node:dns/promises', () => ({
  lookup: dnsMock.lookupMock
}));

const lookupMock = dnsMock.lookupMock;

vi.mock('undici', () => ({
  Agent: agentModule.Agent
}));

import {
  DEFAULT_WEBHOOK_ATTEMPTS,
  WEBHOOK_RETRY_BASE_MS,
  __testCreateDatabase,
  __testResetWebhookCircuitBreaker,
  __testResetWebhookCache,
  __testResetWorkerSecretCache,
  loadWorkerConfig,
  processScanJob,
  startWorker,
  type ScanJobData,
  type WorkerDependencies
} from '../worker/src/worker.ts';
import type { Metrics } from '../metrics/index.ts';
import type { ScannerResult } from '../worker/src/scanners.ts';

type TestEnv = Record<string, string>;

const WORKER_ENV_BASE: TestEnv = {
  DATABASE_URL: 'postgres://localhost:5432/app',
  REDIS_URL: 'redis://localhost:6379',
  SCAN_QUEUE_NAME: 'scan-jobs',
  MAX_CONCURRENCY: '4',
  SCAN_TIMEOUT_S: '900',
  REDIS_TLS_REJECT_UNAUTHORIZED: 'true',
  WEBHOOK_SECRET_KEY: Buffer.alloc(32, 0x21).toString('base64')
};

const secretsSendMock = secretsModule.sendMock;

describe('loadWorkerConfig', () => {
  afterEach(() => {
    secretsSendMock.mockReset();
    __testResetWorkerSecretCache();
  });

  it('parses worker environment into runtime config', async () => {
    const config = await loadWorkerConfig(WORKER_ENV_BASE);

    expect(config).toMatchObject({
      databaseUrl: WORKER_ENV_BASE.DATABASE_URL,
      redisUrl: WORKER_ENV_BASE.REDIS_URL,
      scanQueueName: WORKER_ENV_BASE.SCAN_QUEUE_NAME,
      maxConcurrency: 4,
      scanTimeoutSeconds: 900,
      redisTls: { rejectUnauthorized: true },
      telemetryEnabled: false
    });
    expect(Buffer.isBuffer(config.webhookSecretKey)).toBe(true);
    expect(config.webhookSecretKey.length).toBe(32);
  });

  it('throws when required redis url is missing', async () => {
    const brokenEnv: TestEnv = {
      ...WORKER_ENV_BASE
    };
    delete brokenEnv.REDIS_URL;

    await expect(loadWorkerConfig(brokenEnv)).rejects.toThrow(/REDIS_URL must be configured/i);
  });

  it('rejects invalid TLS boolean flags', async () => {
    const invalidEnv: TestEnv = {
      ...WORKER_ENV_BASE,
      REDIS_TLS_REJECT_UNAUTHORIZED: 'maybe'
    };

    await expect(loadWorkerConfig(invalidEnv)).rejects.toThrow(
      /REDIS_TLS_REJECT_UNAUTHORIZED must be a boolean value/i
    );
  });

  it('parses telemetry flag for worker runtime', async () => {
    const config = await loadWorkerConfig({
      ...WORKER_ENV_BASE,
      TELEMETRY_ENABLED: 'true'
    });

    expect(config.telemetryEnabled).toBe(true);
  });

  it('resolves Secrets Manager URIs for database configuration', async () => {
    secretsSendMock.mockResolvedValueOnce({ SecretString: 'postgres://aws/worker' });

    const config = await loadWorkerConfig({
      ...WORKER_ENV_BASE,
      DATABASE_URL: 'secretsmanager://worker/db'
    });

    expect(config.databaseUrl).toBe('postgres://aws/worker');
    expect(secretsSendMock).toHaveBeenCalledTimes(1);
  });

  it('resolves Secrets Manager URIs for redis configuration', async () => {
    secretsSendMock.mockResolvedValueOnce({ SecretString: 'redis://aws/worker' });

    const config = await loadWorkerConfig({
      ...WORKER_ENV_BASE,
      REDIS_URL: 'secretsmanager://worker/redis'
    });

    expect(config.redisUrl).toBe('redis://aws/worker');
  });
});

type QueryCall = { text: string; values?: unknown[] };

type DbQueryMock = ReturnType<typeof vi.fn<{ rows: unknown[] }, [string, unknown[] | undefined]>>;

describe('database transaction helper', () => {
  afterEach(() => {
    pgModule.poolQueryMock.mockReset();
    pgModule.poolQueryMock.mockImplementation(() => Promise.resolve({ rows: [] }));
    pgModule.connectMock.mockReset();
  });

  it('propagates BEGIN failures and releases the client with the error', async () => {
    const beginError = new Error('begin failed');
    const releaseMock = vi.fn();
    let handlerInvoked = false;

    const clientQuery = vi.fn(async (text: string, _values?: unknown[]) => {
      if (text === 'BEGIN') {
        throw beginError;
      }
      return { rows: [] };
    });

    pgModule.connectMock.mockImplementationOnce(async () => ({
      query: clientQuery,
      release: releaseMock
    }));

    const db = __testCreateDatabase('postgres://test');

    await expect(
      db.transaction(async () => {
        handlerInvoked = true;
        return null;
      })
    ).rejects.toThrow(beginError);

    expect(handlerInvoked).toBe(false);
    expect(clientQuery).toHaveBeenCalledTimes(1);
    expect(clientQuery).toHaveBeenCalledWith('BEGIN', []);
    expect(releaseMock).toHaveBeenCalledTimes(1);
    expect(releaseMock).toHaveBeenCalledWith(beginError);
  });

  it('rolls back and releases the client when COMMIT fails', async () => {
    const releaseMock = vi.fn();
    const commitError = new Error('commit failed');
    const queryCalls: string[] = [];

    const clientQuery = vi.fn(async (text: string, _values?: unknown[]) => {
      queryCalls.push(text);
      if (text === 'COMMIT') {
        throw commitError;
      }
      return { rows: [] };
    });

    pgModule.connectMock.mockImplementationOnce(async () => ({
      query: clientQuery,
      release: releaseMock
    }));

    const db = __testCreateDatabase('postgres://test');

    await expect(
      db.transaction(async (client) => {
        await client.query('SELECT 1');
        return 'ok';
      })
    ).rejects.toThrow(commitError);

    expect(clientQuery).toHaveBeenCalledWith('BEGIN', []);
    expect(clientQuery).toHaveBeenCalledWith('SELECT 1', []);
    expect(clientQuery).toHaveBeenCalledWith('COMMIT', []);
    expect(queryCalls.filter((text) => text === 'ROLLBACK').length).toBe(1);
    expect(queryCalls.indexOf('ROLLBACK')).toBeGreaterThan(queryCalls.indexOf('COMMIT'));
    expect(releaseMock).toHaveBeenCalledTimes(1);
    expect(releaseMock).toHaveBeenCalledWith(commitError);
  });
});

type ScanRecordRow = {
  readonly scan_id: string;
  readonly project_id: string;
  readonly artifact_id: string;
  readonly tenant_id: string;
  readonly policy_id: string | null;
  readonly artifact_type: string;
  readonly artifact_ref: Record<string, unknown>;
  readonly artifact_metadata: Record<string, unknown> | null;
};

type WebhookRow = {
  readonly id: string;
  readonly url: string;
  readonly secret_ciphertext: Buffer | null;
  readonly secret_iv: Buffer | null;
  readonly secret_auth_tag: Buffer | null;
  readonly secret_last_four: string | null;
  readonly events: string[] | null;
};

type PlainWebhookRow = {
  readonly id: string;
  readonly url: string;
  readonly secret: string | null;
  readonly events: string[] | null;
};

function createWebhookRow(secret: string | null, overrides: Partial<WebhookRow> = {}): WebhookRow {
  if (!secret) {
    return {
      id: overrides.id ?? 'webhook-1',
      url: overrides.url ?? 'https://example.com/webhook',
      secret_ciphertext: null,
      secret_iv: null,
      secret_auth_tag: null,
      secret_last_four: null,
      events: overrides.events ?? []
    } satisfies WebhookRow;
  }

  const iv = Buffer.alloc(12, 0x01);
  const cipher = createCipheriv('aes-256-gcm', TEST_WEBHOOK_SECRET_KEY, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    id: overrides.id ?? 'webhook-1',
    url: overrides.url ?? 'https://example.com/webhook',
    secret_ciphertext: ciphertext,
    secret_iv: iv,
    secret_auth_tag: authTag,
    secret_last_four: secret.slice(-4) || null,
    events: overrides.events ?? []
  } satisfies WebhookRow;
}

function normalizeWebhookRow(row: WebhookRow | PlainWebhookRow): WebhookRow {
  if ('secret_ciphertext' in row) {
    return row;
  }

  return createWebhookRow(row.secret, {
    id: row.id,
    url: row.url,
    events: row.events ?? []
  });
}

function createMetricsMocks() {
  const timer = vi.fn();
  const scanDurationHistogram = {
    startTimer: vi.fn(() => timer)
  };
  const webhookOutcomeCounter = {
    inc: vi.fn()
  };
  const queueDepthGauge = {
    set: vi.fn()
  };
  const noticeBuildHistogram = {
    startTimer: vi.fn(() => () => {})
  };
  const feedImportCounter = {
    inc: vi.fn()
  };
  const vexStateGauge = {
    set: vi.fn()
  };
  const vexNoiseGauge = {
    set: vi.fn()
  };
  const vexDowngradedCounter = {
    inc: vi.fn()
  };
  const registry = {
    metrics: vi.fn(() => Promise.resolve('')),
    contentType: 'text/plain'
  };

  const metrics: Metrics = {
    registry,
    queueDepthGauge,
    scanDurationHistogram,
    noticeBuildHistogram,
    webhookOutcomeCounter,
    feedImportCounter,
    vexStateGauge,
    vexNoiseGauge,
    vexDowngradedCounter,
    purgeDurationHistogram: { startTimer: vi.fn(() => () => {}) }
  };

  return { metrics, timer, webhookOutcomeCounter, scanDurationHistogram };
}

function createDbQuery(
  calls: QueryCall[],
  record: ScanRecordRow,
  webhooks: Array<WebhookRow | PlainWebhookRow>,
  options?: {
    policyRules?: Record<string, unknown>;
    events?: string[];
    policyExceptions?: Array<Record<string, unknown>>;
    osvCacheRows?: Array<{ package_purl: string; vulnerabilities: OsvVulnerability[]; fetched_at: string }>;
  }
): DbQueryMock {
  return vi.fn((text: string, values?: unknown[]) => {
    calls.push({ text, values });
    options?.events?.push(text);

    if (text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK') {
      return Promise.resolve({ rows: [] });
    }

    if (text.includes('FROM scans')) {
      return Promise.resolve({ rows: [record] });
    }

    if (text.includes('FROM webhooks')) {
      return Promise.resolve({ rows: webhooks.map(normalizeWebhookRow) });
    }

    if (text.includes('FROM tenants')) {
      return Promise.resolve({ rows: [{ metadata: { active_feed_version: '2024.05' } }] });
    }

    if (text.includes('FROM policies')) {
      return Promise.resolve({ rows: options?.policyRules ? [{ rules: options.policyRules }] : [] });
    }

    if (text.includes('FROM policy_exceptions')) {
      return Promise.resolve({ rows: options?.policyExceptions ?? [] });
    }

    if (text.includes('FROM osv_cache')) {
      return Promise.resolve({ rows: options?.osvCacheRows ?? [] });
    }

    return Promise.resolve({ rows: [] });
  });
}

function createDbAdapter(query: DbQueryMock): WorkerDependencies['db'] {
  return {
    query,
    async transaction(handler) {
      await query('BEGIN');
      try {
        const result = await handler({
          query: (text, values) => query(text, values)
        });
        await query('COMMIT');
        return result;
      } catch (error) {
        await query('ROLLBACK');
        throw error;
      }
    }
  };
}

describe('worker pipeline', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    lookupMock.mockReset();
    lookupMock.mockResolvedValue([{ address: '203.0.113.1', family: 4 }]);
    agentModule.Agent.mockClear();
    agentModule.instances.length = 0;
    __testResetWebhookCircuitBreaker();
    __testResetWebhookCache();
  });

  it('classifies a scan without vulnerabilities as pass and delivers webhooks', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-pass',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-pass',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-1',
        url: 'https://example.com/webhook',
        secret: 'shared-secret',
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const events: string[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, { events });

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-pass',
        artifactPath: '/tmp/workspaces/scan-pass/source'
      })
    );

    const scannerResult = {
      packages: [
        {
          name: 'left-pad',
          version: '1.0.0',
          ecosystem: 'npm',
          purl: 'pkg:npm/left-pad@1.0.0'
        }
      ],
      bom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: '2024-01-01T00:00:00.000Z', tools: [] },
        components: []
      },
      licenses: [
        {
          path: 'LICENSE',
          spdxId: 'MIT',
          packageName: 'left-pad'
        }
      ],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => {
      events.push('FETCH');
      return Promise.resolve({ ok: true, status: 200 } as unknown as Response);
    });
    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const idSequence = ['sbom-1', 'license-1', 'finding-1'];
    const generateId = vi.fn(() => {
      const next = idSequence.shift();
      if (!next) {
        throw new Error('Unexpected id request');
      }

      return next;
    });

    const nowSequence = [
      new Date('2024-01-01T00:00:00.000Z'),
      new Date('2024-01-01T00:00:02.000Z')
    ];
    const now = vi.fn(() => {
      const value = nowSequence.shift();
      if (!value) {
        return new Date('2024-01-01T00:00:02.000Z');
      }

      return value;
    });

    const wait = vi.fn(() => Promise.resolve());
    const sendSiemEvent = vi.fn(() => Promise.resolve());
    const syncTicketing = vi.fn(() => Promise.resolve());

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY,
      sendSiemEvent,
      syncTicketing
    };

    await processScanJob(job, dependencies);

    expect(queryCalls.some((call) => call.text === 'BEGIN')).toBe(true);
    expect(queryCalls.some((call) => call.text === 'COMMIT')).toBe(true);

    const sbomInsert = queryCalls.find((call) => call.text.includes('INSERT INTO sboms'));
    expect(sbomInsert?.values).toEqual([
      'sbom-1',
      'project-1',
      'artifact-1',
      'scan-pass',
      'CycloneDX',
      scannerResult.bom,
      0
    ]);

    const licenseInsert = queryCalls.find((call) => call.text.includes('INSERT INTO licenses'));
    expect(licenseInsert?.values).toEqual([
      'license-1',
      'sbom-1',
      'pkg:npm/left-pad@1.0.0',
      'MIT',
      {
        path: 'LICENSE',
        component: 'left-pad',
        spdx: 'MIT'
      }
    ]);

    const legalFindingInsert = queryCalls.find((call) => call.text.includes('INSERT INTO legal_findings'));
    expect(legalFindingInsert?.values).toEqual([
      'finding-1',
      'tenant-1',
      'license-1',
      'scan-pass',
      { notice: true, attribution: true },
      null
    ]);

    const initialUpdate = queryCalls.find(
      (call) =>
        call.text.startsWith('UPDATE scans') &&
        call.text.includes('policy_result = $3') &&
        !call.text.includes('jsonb_set')
    );
    expect(initialUpdate?.values?.[1]).toBe('succeeded');
    expect(initialUpdate?.values?.[2]).toBe('pass');
    expect(initialUpdate?.values?.[4]).toBe(2000);
    expect(initialUpdate?.values?.[3]).toMatchObject({
      policy: { result: 'pass', reasons: [] },
      webhooks: { delivered: 0, failed: 0 }
    });

    const webhookUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(webhookUpdate?.values?.[1]).toEqual({
      delivered: 1,
      failed: 0,
      failures: []
    });

    const evidenceInsert = queryCalls.find((call) => call.text.includes('INSERT INTO evidence_packs'));
    expect(evidenceInsert?.values).toEqual([
      'tenant-1',
      'project-1',
      'scan-pass',
      null,
      expect.objectContaining({
        feed_version: '2024.05',
        notice_version_id: null,
        files: expect.any(Array)
      }),
      null,
      'sha256'
    ]);

    const commitIndex = events.indexOf('COMMIT');
    const fetchIndex = events.indexOf('FETCH');
    expect(commitIndex).toBeGreaterThanOrEqual(0);
    expect(fetchIndex).toBeGreaterThan(commitIndex);
    const webhookUpdateIndex = events.findIndex((event) => event.includes('jsonb_set'));
    expect(webhookUpdateIndex).toBeGreaterThan(fetchIndex);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const webhookCall = fetchImpl.mock.calls[0];
    const body = (webhookCall?.[1] as { body?: string } | undefined)?.body;
    expect(body).toBeDefined();
    const headers = (webhookCall?.[1] as { headers?: Record<string, string> } | undefined)?.headers ?? {};
    const signature = headers['X-Webhook-Signature'];
    expect(signature).toBe(
      body ? `sha256=${createHmac('sha256', 'shared-secret').update(body).digest('hex')}` : undefined
    );
    expect(headers['X-Otomatik-Webhook-Id']).toBe('webhook-1');
    expect(headers['X-Otomatik-Webhook-Event']).toBe('scan.completed');

    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'success' });
    expect(sendSiemEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'scan.completed',
        tenantId: 'tenant-1',
        projectId: 'project-1',
        scanId: 'scan-pass',
        policyResult: 'pass',
        totalVulnerabilities: 0,
        downgradedByVex: 0
      })
    );
    expect(syncTicketing).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'resolve',
        tenantId: 'tenant-1',
        projectId: 'project-1',
        scanId: 'scan-pass'
      })
    );
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
    expect(cleanupWorkspaceMock).toHaveBeenCalledWith('/tmp/workspaces/scan-pass');
    expect(wait).not.toHaveBeenCalled();
    expect(lookupMock).toHaveBeenCalledWith('example.com', { all: true });

    const webhookOptions = fetchImpl.mock.calls[0]?.[1] as {
      signal?: AbortSignal;
      redirect?: string;
      dispatcher?: unknown;
    } | undefined;
    expect(webhookOptions?.signal).toBeInstanceOf(AbortSignal);
    expect(webhookOptions?.redirect).toBe('manual');
    expect(webhookOptions?.dispatcher).toBeDefined();
  });

  it('caches decrypted webhooks for the ttl window', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-cache',
      project_id: 'project-cache',
      artifact_id: 'artifact-cache',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-cache',
      project_id: 'project-cache',
      artifact_id: 'artifact-cache',
      tenant_id: 'tenant-cache',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/cache.git', commit: '123abc' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-cache',
        url: 'https://example.com/webhook',
        secret: 'cached-secret',
        events: ['scan.completed']
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);
    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-cache',
        artifactPath: '/tmp/workspaces/scan-cache/source'
      })
    );

    const scannerResult: ScannerResult = {
      packages: [],
      bom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: '2024-01-01T00:00:00.000Z', tools: [] },
        components: []
      },
      licenses: [],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    let counter = 0;
    const generateId = vi.fn(() => {
      counter += 1;
      return `gen-${counter}`;
    });

    const now = vi.fn(() => new Date('2024-01-01T00:00:00.000Z'));
    const wait = vi.fn(() => Promise.resolve());
    const sendSiemEvent = vi.fn(() => Promise.resolve());
    const syncTicketing = vi.fn(() => Promise.resolve());

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY,
      sendSiemEvent,
      syncTicketing
    };

    await processScanJob(job, dependencies);
    await processScanJob(job, dependencies);

    const webhookSelectCalls = queryCalls.filter((call) => call.text.includes('FROM webhooks'));
    expect(webhookSelectCalls).toHaveLength(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'success' });
  });

  it('invalidates the webhook cache after delivery failures', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-cache-failure',
      project_id: 'project-cache',
      artifact_id: 'artifact-cache',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-cache-failure',
      project_id: 'project-cache',
      artifact_id: 'artifact-cache',
      tenant_id: 'tenant-cache',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/cache.git', commit: '123abc' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-cache',
        url: 'https://example.com/webhook',
        secret: 'cached-secret',
        events: ['scan.completed']
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);
    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-cache',
        artifactPath: '/tmp/workspaces/scan-cache/source'
      })
    );

    const scannerResult: ScannerResult = {
      packages: [],
      bom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: '2024-01-01T00:00:00.000Z', tools: [] },
        components: []
      },
      licenses: [],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi
      .fn<Promise<Response>, [string, unknown]>
      (() => Promise.resolve({ ok: false, status: 500 } as unknown as Response));

    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    let counter = 0;
    const generateId = vi.fn(() => {
      counter += 1;
      return `gen-${counter}`;
    });

    const now = vi.fn(() => new Date('2024-01-01T00:00:00.000Z'));
    const wait = vi.fn(() => Promise.resolve());
    const sendSiemEvent = vi.fn(() => Promise.resolve());
    const syncTicketing = vi.fn(() => Promise.resolve());

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY,
      sendSiemEvent,
      syncTicketing
    };

    await processScanJob(job, dependencies);
    fetchImpl.mockImplementation(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    await processScanJob(job, dependencies);

    const webhookSelectCalls = queryCalls.filter((call) => call.text.includes('FROM webhooks'));
    expect(webhookSelectCalls).toHaveLength(2);
    expect(fetchImpl.mock.calls.length).toBeGreaterThanOrEqual(DEFAULT_WEBHOOK_ATTEMPTS);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
  });

  it('delivers webhooks with a guarded dispatcher and closes it after success', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-dispatcher-success',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-dispatcher-success',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-guarded',
        url: 'https://webhooks.example.com/hook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, {
      osvCacheRows: [
        { package_purl: 'pkg:npm/left-pad@1.0.0', vulnerabilities: [], fetched_at: '2024-01-01T00:00:00.000Z' }
      ]
    });

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-dispatcher-success',
        artifactPath: '/tmp/workspaces/scan-dispatcher-success/source'
      })
    );

    const scannerResult = {
      packages: [],
      bom: {},
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const runScanners = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const wait = vi.fn(() => Promise.resolve());
    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: () => 'sbom-1',
      now: () => new Date('2023-01-01T00:00:00.000Z'),
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(agentModule.Agent).toHaveBeenCalledTimes(1);
    const dispatcherInstance = agentModule.instances[0];
    expect(dispatcherInstance).toBeDefined();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const callOptions = fetchImpl.mock.calls[0]?.[1] as { dispatcher?: unknown; redirect?: string } | undefined;
    expect(callOptions?.dispatcher).toBe(dispatcherInstance);
    expect(callOptions?.redirect).toBe('manual');
    expect(dispatcherInstance?.close).toHaveBeenCalledTimes(1);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'success' });
  });

  it('purges expired osv cache rows before invoking scanners', async () => {
    // Suresi dolmus kayitlar yalniz ag acikken silinir; air-gap modunda eski veri korunur.
    vi.stubEnv('ALLOW_NETWORK_FETCH', 'true');
    const job: ScanJobData = {
      scan_id: 'scan-cache-prune',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-cache-prune',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [];
    const queryCalls: QueryCall[] = [];
    const osvCacheRows = [
      {
        package_purl: 'pkg:npm/fresh@1.0.0',
        vulnerabilities: [
          {
            id: 'OSV-2024-0001',
            summary: 'Placeholder'
          } satisfies OsvVulnerability
        ],
        fetched_at: '2024-01-01T12:00:00.000Z'
      },
      {
        package_purl: 'pkg:npm/stale@2.0.0',
        vulnerabilities: [],
        fetched_at: '2023-12-30T00:00:00.000Z'
      }
    ];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, { osvCacheRows });

    const scannerResult = {
      packages: [],
      bom: {},
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const runScannersMock = vi.fn(async (_artifactPath: string, options?: { cache?: Map<string, unknown> }) => {
      const cache = options?.cache ?? new Map();
      expect(cache.get('pkg:npm/fresh@1.0.0')).toEqual(osvCacheRows[0]?.vulnerabilities);
      expect(cache.has('pkg:npm/stale@2.0.0')).toBe(false);
      return scannerResult;
    });

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: vi.fn(() =>
        Promise.resolve({
          workspacePath: '/tmp/workspaces/scan-cache-prune',
          artifactPath: '/tmp/workspaces/scan-cache-prune/source'
        })
      ),
      runScanners: runScannersMock as unknown as WorkerDependencies['runScanners'],
      cleanupWorkspace: vi.fn(() => Promise.resolve()),
      metrics: createMetricsMocks().metrics,
      fetchImpl: vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response)),
      generateId: () => 'sbom-cache',
      now: () => new Date('2024-01-02T00:00:00.000Z'),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(runScannersMock).toHaveBeenCalledTimes(1);
    const deleteCall = queryCalls.find((call) => call.text.includes('DELETE FROM osv_cache'));
    expect(deleteCall).toBeDefined();
    expect(deleteCall?.values).toEqual([
      'tenant-1',
      '2024.05',
      new Date('2024-01-01T00:00:00.000Z')
    ]);
  });

  it('reuses stale osv cache entries when network fetches are disabled', async () => {
    const originalAllow = process.env.ALLOW_NETWORK_FETCH;
    process.env.ALLOW_NETWORK_FETCH = 'false';

    const job: ScanJobData = {
      scan_id: 'scan-cache-offline',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-cache-offline',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [];
    const queryCalls: QueryCall[] = [];
    const osvCacheRows = [
      {
        package_purl: 'pkg:npm/stale@2.0.0',
        vulnerabilities: [{ id: 'OSV-2024-0002' } satisfies OsvVulnerability],
        fetched_at: '2023-01-01T00:00:00.000Z'
      }
    ];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, { osvCacheRows });

    const scannerResult = {
      packages: [],
      bom: {},
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const runScannersMock = vi.fn(async (_artifactPath: string, options?: { cache?: Map<string, unknown> }) => {
      const cache = options?.cache ?? new Map();
      expect(cache.get('pkg:npm/stale@2.0.0')).toEqual(osvCacheRows[0]?.vulnerabilities);
      return scannerResult;
    });

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: vi.fn(() =>
        Promise.resolve({
          workspacePath: '/tmp/workspaces/scan-cache-offline',
          artifactPath: '/tmp/workspaces/scan-cache-offline/source'
        })
      ),
      runScanners: runScannersMock as unknown as WorkerDependencies['runScanners'],
      cleanupWorkspace: vi.fn(() => Promise.resolve()),
      metrics: createMetricsMocks().metrics,
      fetchImpl: vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response)),
      generateId: () => 'sbom-cache-offline',
      now: () => new Date('2024-02-01T00:00:00.000Z'),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    try {
      await processScanJob(job, dependencies);
    } finally {
      if (originalAllow === undefined) {
        delete process.env.ALLOW_NETWORK_FETCH;
      } else {
        process.env.ALLOW_NETWORK_FETCH = originalAllow;
      }
    }

    expect(runScannersMock).toHaveBeenCalledTimes(1);
    const deleteCall = queryCalls.find((call) => call.text.includes('DELETE FROM osv_cache'));
    expect(deleteCall).toBeUndefined();
  });

  it('records purge manifest entries for the evidence pack', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-purge-manifest',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-purge-manifest',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const workspaceRoot = await mkdtemp(join(tmpdir(), 'atlas-purge-'));
    await mkdir(join(workspaceRoot, 'src'));
    await writeFile(join(workspaceRoot, 'src', 'index.js'), 'console.log("hello");');
    await writeFile(join(workspaceRoot, 'README.md'), '# Docs');
    await mkdir(join(workspaceRoot, '.git'), { recursive: true });
    await writeFile(join(workspaceRoot, '.git', 'config'), '[core]');
    await mkdir(join(workspaceRoot, 'node_modules/pkg'), { recursive: true });
    await writeFile(join(workspaceRoot, 'node_modules/pkg/index.js'), 'module.exports = {};');
    await symlink(join(workspaceRoot, 'README.md'), join(workspaceRoot, 'docs-link'));

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, []);

    const scannerResult: ScannerResult = {
      packages: [],
      bom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] },
      vulnerabilities: [],
      licenses: []
    };

    let capturedManifest: Record<string, unknown> | null = null;
    const buildEvidencePack = vi.fn(async (options: Parameters<WorkerDependencies['buildEvidencePack']>[0]) => {
      capturedManifest = options.purgeManifest ?? null;
      return {
        archive: Buffer.alloc(0),
        manifest: {},
        hashAlgorithm: 'sha256'
      };
    });

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: vi.fn(() =>
        Promise.resolve({ workspacePath: workspaceRoot, artifactPath: join(workspaceRoot, 'src') })
      ),
      runScanners: vi.fn(() => Promise.resolve(scannerResult)),
      cleanupWorkspace: vi.fn(() => Promise.resolve()),
      buildEvidencePack,
      metrics: createMetricsMocks().metrics,
      fetchImpl: vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response)),
      generateId: () => 'sbom-purge',
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(buildEvidencePack).toHaveBeenCalled();
    expect(capturedManifest).not.toBeNull();
    const items = (capturedManifest as { items?: Array<Record<string, unknown>> })?.items ?? [];
    const manifestPaths = items.map((item) => item?.path);
    expect(manifestPaths).toContain('README.md');
    expect(items.find((item) => item?.path === 'src/index.js')?.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(manifestPaths.some((path) => typeof path === 'string' && path.startsWith('.git'))).toBe(false);
    expect(manifestPaths.some((path) => typeof path === 'string' && path.startsWith('node_modules'))).toBe(false);
    const symlinkEntry = items.find((item) => item?.path === 'docs-link');
    expect(symlinkEntry?.type).toBe('symlink');

    await dependencies.cleanupWorkspace(workspaceRoot);
  });

  it('rejects webhooks resolving to private addresses before dispatch', async () => {
    lookupMock.mockResolvedValue([{ address: '10.0.0.5', family: 4 }]);

    const job: ScanJobData = {
      scan_id: 'scan-private-webhook',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-private-webhook',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-private',
        url: 'https://internal.example.com/webhook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, {
      osvCacheRows: [
        { package_purl: 'pkg:npm/express@4.18.0', vulnerabilities: [], fetched_at: '2024-03-01T00:00:00.000Z' }
      ]
    });
    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({ workspacePath: '/tmp/workspaces/scan-private-webhook', artifactPath: '/tmp/workspaces/scan-private-webhook/source' })
    );

    const scannerResult = {
      packages: [],
      bom: {},
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const runScanners = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const wait = vi.fn(() => Promise.resolve());
    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: () => 'sbom-1',
      now: () => new Date('2023-01-01T00:00:00.000Z'),
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(agentModule.Agent).not.toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
  });

  it('rejects webhooks targeting IPv4-mapped IPv6 private addresses', async () => {
    lookupMock.mockResolvedValue([{ address: '::ffff:10.0.0.5', family: 6 }]);

    const job: ScanJobData = {
      scan_id: 'scan-private-webhook-ipv4-mapped',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-private-webhook-ipv4-mapped',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      tenant_id: 'tenant-1',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-private-ipv4-mapped',
        url: 'https://internal.example.com/webhook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);
    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({ workspacePath: '/tmp/workspaces/scan-private-webhook-ipv4-mapped', artifactPath: '/tmp/workspaces/scan-private-webhook-ipv4-mapped/source' })
    );

    const scannerResult = {
      packages: [],
      bom: {},
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const runScanners = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as Response));
    const wait = vi.fn(() => Promise.resolve());
    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: () => 'sbom-1',
      now: () => new Date('2023-01-01T00:00:00.000Z'),
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(agentModule.Agent).not.toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
  });

  it('fails webhook deliveries that attempt redirects', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-webhook-redirect',
      project_id: 'project-redirect',
      artifact_id: 'artifact-redirect',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-webhook-redirect',
      project_id: 'project-redirect',
      artifact_id: 'artifact-redirect',
      tenant_id: 'tenant-redirect',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'abc123' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-redirect',
        url: 'https://hooks.example.com/redirect',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);
    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({ workspacePath: '/tmp/workspaces/scan-webhook-redirect', artifactPath: '/tmp/workspaces/scan-webhook-redirect/source' })
    );

    const scannerResult = {
      packages: [],
      bom: {},
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const runScanners = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() =>
      Promise.resolve({
        status: 302,
        ok: false
      } as Response)
    );
    const wait = vi.fn(() => Promise.resolve());
    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: () => 'sbom-1',
      now: () => new Date('2023-01-01T00:00:00.000Z'),
      wait,
      webhookRetryAttempts: 2,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(wait).toHaveBeenCalledTimes(1);
    const [delay] = wait.mock.calls[0] ?? [0];
    expect(delay).toBeGreaterThanOrEqual(WEBHOOK_RETRY_BASE_MS * 0.75);
    expect(delay).toBeLessThanOrEqual(WEBHOOK_RETRY_BASE_MS * 1.25);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
  });

  it('opens the webhook circuit after repeated failures and recovers after cooldown', async () => {
    const baseTime = Date.UTC(2024, 1, 1, 0, 0, 0);
    let currentTime = 0;
    const now = vi.fn(() => new Date(baseTime + currentTime));

    const scannerResult = {
      packages: [],
      bom: { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, components: [] },
      vulnerabilities: [],
      licenses: [],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }
    } satisfies ScannerResult;

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({ workspacePath: '/tmp/workspaces/circuit', artifactPath: '/tmp/workspaces/circuit/source' })
    );
    const runScanners = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn();
    fetchImpl.mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response);
    fetchImpl.mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response);
    fetchImpl.mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response);
    fetchImpl.mockResolvedValue({
      ok: true,
      status: 200,
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0))
    } as unknown as Response);

    const wait = vi.fn(() => Promise.resolve());
    const { metrics, webhookOutcomeCounter } = createMetricsMocks();
    let idCounter = 0;
    const generateId = vi.fn(() => `generated-${idCounter++}`);

    async function runScan(attempt: number): Promise<void> {
      const scanId = `scan-circuit-${attempt}`;
      const job: ScanJobData = {
        scan_id: scanId,
        project_id: 'project-circuit',
        artifact_id: `artifact-circuit-${attempt}`,
        policy_id: null
      };

      const scanRecord: ScanRecordRow = {
        scan_id: scanId,
        project_id: job.project_id,
        artifact_id: job.artifact_id,
        tenant_id: 'tenant-circuit',
        policy_id: null,
        artifact_type: 'git',
        artifact_ref: { url: 'https://example.com/repo.git', commit: 'main' },
        artifact_metadata: {}
      };

      const webhooks: Array<WebhookRow | PlainWebhookRow> = [
        {
          id: `webhook-${attempt}`,
          url: 'https://hooks.example.com/notify',
          secret: null,
          events: []
        }
      ];

      const queryCalls: QueryCall[] = [];
      const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

      const dependencies: WorkerDependencies = {
        db: createDbAdapter(dbQuery),
        fetchArtifact: fetchArtifactMock,
        runScanners,
        cleanupWorkspace: cleanupWorkspaceMock,
        metrics,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        generateId,
        now,
        wait,
        webhookRetryAttempts: 1,
        webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
      };

      await processScanJob(job, dependencies);
    }

    currentTime = 0;
    await runScan(1);
    currentTime = 10_000;
    await runScan(2);
    currentTime = 20_000;
    await runScan(3);

    expect(fetchImpl).toHaveBeenCalledTimes(3);

    currentTime = 25_000;
    await runScan(4);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(webhookOutcomeCounter.inc).toHaveBeenLastCalledWith({ result: 'failed' });

    currentTime = 120_000;
    await runScan(5);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
    expect(webhookOutcomeCounter.inc).toHaveBeenLastCalledWith({ result: 'success' });
  });

  it('classifies medium vulnerabilities as warn and retries webhooks', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-warn',
      project_id: 'project-2',
      artifact_id: 'artifact-2',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-warn',
      project_id: 'project-2',
      artifact_id: 'artifact-2',
      tenant_id: 'tenant-2',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'def456' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-2',
        url: 'https://example.com/webhook',
        secret: null,
        events: ['scan.completed']
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-warn',
        artifactPath: '/tmp/workspaces/scan-warn/source'
      })
    );

    const scannerResult = {
      packages: [
        {
          name: 'lodash',
          version: '4.17.0',
          ecosystem: 'npm',
          purl: 'pkg:npm/lodash@4.17.0'
        }
      ],
      bom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: '2024-02-01T00:00:00.000Z', tools: [] },
        components: []
      },
      licenses: [
        {
          path: 'LICENSE',
          spdxId: 'MIT',
          packageName: 'lodash'
        }
      ],
      vulnerabilities: [
        {
          package: {
            name: 'lodash',
            version: '4.17.0',
            ecosystem: 'npm',
            purl: 'pkg:npm/lodash@4.17.0'
          },
          vulnerabilities: [
            {
              id: 'OSV-2024-XYZ',
              summary: 'Example vulnerability',
              severity: [{ score: '5.5' }]
            }
          ]
        }
      ]
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());

    const fetchImpl = vi
      .fn(() => Promise.resolve({ ok: false, status: 500 } as unknown as Response))
      .mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response)
      .mockResolvedValueOnce({ ok: true, status: 200 } as unknown as Response);

    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const idSequence = ['sbom-2', 'license-2', 'finding-2', 'vuln-2'];
    const generateId = vi.fn(() => {
      const next = idSequence.shift();
      if (!next) {
        throw new Error('Unexpected id request');
      }

      return next;
    });

    const nowSequence = [
      new Date('2024-02-01T00:00:00.000Z'),
      new Date('2024-02-01T00:00:01.500Z')
    ];
    const now = vi.fn(() => {
      const value = nowSequence.shift();
      return value ?? new Date('2024-02-01T00:00:01.500Z');
    });

    const wait = vi.fn(() => Promise.resolve());

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(queryCalls.some((call) => call.text === 'BEGIN')).toBe(true);
    expect(queryCalls.some((call) => call.text === 'COMMIT')).toBe(true);

    const updateCall = queryCalls.find(
      (call) =>
        call.text.startsWith('UPDATE scans') &&
        call.text.includes('policy_result = $3') &&
        !call.text.includes('jsonb_set')
    );
    expect(updateCall?.values?.[2]).toBe('warn');
    expect(updateCall?.values?.[4]).toBe(1500);
    expect(updateCall?.values?.[3]).toMatchObject({
      policy: { result: 'warn', reasons: [expect.stringMatching(/CVSS 5\.5/)] },
      webhooks: { failed: 0 }
    });

    const webhookUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(webhookUpdate?.values?.[1]).toEqual({ delivered: 1, failed: 0, failures: [] });

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(wait).toHaveBeenCalledTimes(1);
    const [delay] = wait.mock.calls[0] ?? [0];
    expect(delay).toBeGreaterThanOrEqual(WEBHOOK_RETRY_BASE_MS * 0.75);
    expect(delay).toBeLessThanOrEqual(WEBHOOK_RETRY_BASE_MS * 1.25);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'success' });
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
    expect(lookupMock).toHaveBeenCalledWith('example.com', { all: true });
  });

  it('classifies high vulnerabilities as fail and records webhook failures', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-fail',
      project_id: 'project-3',
      artifact_id: 'artifact-3',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-fail',
      project_id: 'project-3',
      artifact_id: 'artifact-3',
      tenant_id: 'tenant-3',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'ghi789' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-3',
        url: 'https://example.com/webhook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-fail',
        artifactPath: '/tmp/workspaces/scan-fail/source'
      })
    );

    const scannerResult = {
      packages: [
        {
          name: 'express',
          version: '4.18.0',
          ecosystem: 'npm',
          purl: 'pkg:npm/express@4.18.0'
        }
      ],
      bom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: '2024-03-01T00:00:00.000Z', tools: [] },
        components: []
      },
      licenses: [
        {
          path: 'LICENSE',
          spdxId: 'MIT',
          packageName: 'express'
        }
      ],
      vulnerabilities: [
        {
          package: {
            name: 'express',
            version: '4.18.0',
            ecosystem: 'npm',
            purl: 'pkg:npm/express@4.18.0'
          },
          vulnerabilities: [
            {
              id: 'CVE-9999-0001',
              summary: 'Critical vulnerability',
              severity: [{ score: 8.9 }]
            }
          ]
        }
      ]
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: false, status: 500 } as unknown as Response));

    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const idSequence = ['sbom-3', 'license-3', 'finding-3', 'vuln-3'];
    const generateId = vi.fn(() => {
      const next = idSequence.shift();
      if (!next) {
        throw new Error('Unexpected id request');
      }

      return next;
    });

    const nowSequence = [
      new Date('2024-03-01T00:00:00.000Z'),
      new Date('2024-03-01T00:00:05.000Z')
    ];
    const now = vi.fn(() => {
      const value = nowSequence.shift();
      return value ?? new Date('2024-03-01T00:00:05.000Z');
    });

    const wait = vi.fn(() => Promise.resolve());

    const syncTicketing = vi.fn(() => Promise.resolve());

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: 2,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY,
      syncTicketing
    };

    await processScanJob(job, dependencies);

    expect(queryCalls.some((call) => call.text === 'BEGIN')).toBe(true);
    expect(queryCalls.some((call) => call.text === 'COMMIT')).toBe(true);

    const updateCall = queryCalls.find(
      (call) =>
        call.text.startsWith('UPDATE scans') &&
        call.text.includes('policy_result = $3') &&
        !call.text.includes('jsonb_set')
    );
    expect(updateCall?.values?.[2]).toBe('fail');
    expect(updateCall?.values?.[4]).toBe(5000);
    expect(updateCall?.values?.[3]).toMatchObject({
      policy: { result: 'fail', reasons: [expect.stringMatching(/CVSS 8\.9/)] },
      webhooks: { failed: 0 }
    });

    const webhookUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(webhookUpdate?.values?.[1]).toEqual({
      delivered: 0,
      failed: 1,
      failures: [expect.objectContaining({ id: 'webhook-3', error: expect.stringMatching(/status 500/) })]
    });

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
    expect(lookupMock).toHaveBeenCalledWith('example.com', { all: true });
    expect(syncTicketing).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'open',
        tenantId: 'tenant-3',
        projectId: 'project-3',
        scanId: 'scan-fail'
      })
    );
  });

  it('applies an approved policy exception to downgrade a failure', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-exception',
      project_id: 'project-4',
      artifact_id: 'artifact-4',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-exception',
      project_id: 'project-4',
      artifact_id: 'artifact-4',
      tenant_id: 'tenant-4',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'jkl012' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [];
    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, {
      policyExceptions: [
        {
          id: 'exc-1',
          tenant_id: 'tenant-4',
          project_id: 'project-4',
          component_purl: 'pkg:npm/express@4.18.0',
          scope: 'package',
          status: 'approved',
          expires_at: '2099-01-01T00:00:00.000Z'
        }
      ]
    });

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-exception',
        artifactPath: '/tmp/workspaces/scan-exception/source'
      })
    );

    const scannerResult: ScannerResult = {
      packages: [
        { name: 'express', version: '4.18.0', ecosystem: 'npm', purl: 'pkg:npm/express@4.18.0' }
      ],
      bom: { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata: { timestamp: '', tools: [] }, components: [] },
      licenses: [
        { path: 'LICENSE', spdxId: 'MIT', packageName: 'express' }
      ],
      vulnerabilities: [
        {
          package: { name: 'express', version: '4.18.0', ecosystem: 'npm', purl: 'pkg:npm/express@4.18.0' },
          vulnerabilities: [
            { id: 'CVE-2024-0001', summary: 'Example issue', severity: [{ score: 8.1 }] }
          ]
        }
      ]
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as Response));
    const wait = vi.fn(() => Promise.resolve());
    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const idSequence = ['sbom-4', 'license-4', 'finding-4', 'vuln-4'];
    const generateId = vi.fn(() => {
      const next = idSequence.shift();
      if (!next) {
        throw new Error('Unexpected id request');
      }

      return next;
    });

    const scheduleRescan = vi.fn(() => Promise.resolve());

    const now = vi.fn(() => new Date('2024-04-01T00:00:00.000Z'));

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY,
      scheduleRescan
    };

    await processScanJob(job, dependencies);

    const updateCall = queryCalls.find(
      (call) =>
        call.text.startsWith('UPDATE scans') &&
        call.text.includes('policy_result = $3') &&
        !call.text.includes('jsonb_set')
    );

    expect(updateCall?.values?.[2]).toBe('warn');
    expect(updateCall?.values?.[3]).toMatchObject({
      policy: { reasons: expect.arrayContaining([expect.stringContaining('Policy exception applied (package).')]) }
    });
    expect(scheduleRescan).not.toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).not.toHaveBeenCalled();
  });

  it('expires outdated policy exceptions and schedules a rescan', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-expired-exception',
      project_id: 'project-5',
      artifact_id: 'artifact-5',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-expired-exception',
      project_id: 'project-5',
      artifact_id: 'artifact-5',
      tenant_id: 'tenant-5',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'mno345' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [];
    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks, {
      policyExceptions: [
        {
          id: 'exc-2',
          tenant_id: 'tenant-5',
          project_id: 'project-5',
          component_purl: 'pkg:npm/express@4.18.0',
          scope: 'package',
          status: 'approved',
          expires_at: '2024-01-01T00:00:00.000Z'
        }
      ]
    });

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-expired-exception',
        artifactPath: '/tmp/workspaces/scan-expired-exception/source'
      })
    );

    const scannerResult: ScannerResult = {
      packages: [
        { name: 'express', version: '4.18.0', ecosystem: 'npm', purl: 'pkg:npm/express@4.18.0' }
      ],
      bom: { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata: { timestamp: '', tools: [] }, components: [] },
      licenses: [
        { path: 'LICENSE', spdxId: 'MIT', packageName: 'express' }
      ],
      vulnerabilities: [
        {
          package: { name: 'express', version: '4.18.0', ecosystem: 'npm', purl: 'pkg:npm/express@4.18.0' },
          vulnerabilities: [
            { id: 'CVE-2024-0002', summary: 'Example issue', severity: [{ score: 7.0 }] }
          ]
        }
      ]
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as Response));
    const wait = vi.fn(() => Promise.resolve());
    const { metrics, timer } = createMetricsMocks();

    const idSequence = ['sbom-5', 'license-5', 'finding-5', 'vuln-5'];
    const generateId = vi.fn(() => {
      const next = idSequence.shift();
      if (!next) {
        throw new Error('Unexpected id request');
      }

      return next;
    });

    const scheduleRescan = vi.fn(() => Promise.resolve());

    const now = vi.fn(() => new Date('2024-04-01T00:00:00.000Z'));

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId,
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY,
      scheduleRescan
    };

    await processScanJob(job, dependencies);

    const exceptionUpdate = queryCalls.find((call) => call.text.includes('UPDATE policy_exceptions'));
    expect(exceptionUpdate?.values?.[0]).toEqual(['exc-2']);
    expect(scheduleRescan).toHaveBeenCalledWith({
      projectId: 'project-5',
      tenantId: 'tenant-5',
      reason: 'policy_exception_expired'
    });

    const updateCall = queryCalls.find(
      (call) =>
        call.text.startsWith('UPDATE scans') &&
        call.text.includes('policy_result = $3') &&
        !call.text.includes('jsonb_set')
    );
    expect(updateCall?.values?.[2]).toBe('fail');
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
  });

  it('rejects non-HTTPS webhook targets before delivery', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-http-webhook',
      project_id: 'project-http',
      artifact_id: 'artifact-http',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-http-webhook',
      project_id: 'project-http',
      artifact_id: 'artifact-http',
      tenant_id: 'tenant-http',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-http',
        url: 'http://example.com/webhook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-http-webhook',
        artifactPath: '/tmp/workspaces/scan-http-webhook/source'
      })
    );

    const scannerResult = {
      packages: [],
      bom: { bomFormat: 'CycloneDX', version: 1, components: [] },
      licenses: [],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: vi.fn(() => 'sbom-http'),
      now: vi.fn(() => new Date('2024-05-01T00:00:00.000Z')),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
    expect(lookupMock).not.toHaveBeenCalled();
    const summaryUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(summaryUpdate?.values?.[1]).toMatchObject({ failed: 1 });
  });

  it('rejects webhooks resolving to private networks', async () => {
    lookupMock.mockResolvedValueOnce([{ address: '10.0.0.5', family: 4 }]);

    const job: ScanJobData = {
      scan_id: 'scan-private-webhook',
      project_id: 'project-private',
      artifact_id: 'artifact-private',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-private-webhook',
      project_id: 'project-private',
      artifact_id: 'artifact-private',
      tenant_id: 'tenant-private',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-private',
        url: 'https://internal.example.com/hook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-private-webhook',
        artifactPath: '/tmp/workspaces/scan-private-webhook/source'
      })
    );

    const scannerResult = {
      packages: [],
      bom: { bomFormat: 'CycloneDX', version: 1, components: [] },
      licenses: [],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: vi.fn(() => 'sbom-private'),
      now: vi.fn(() => new Date('2024-05-02T00:00:00.000Z')),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
    expect(lookupMock).toHaveBeenCalledWith('internal.example.com', { all: true });
    const summaryUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(summaryUpdate?.values?.[1]).toMatchObject({ failed: 1 });
  });

  it('rejects webhook responses that attempt redirects', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-webhook-redirect',
      project_id: 'project-redirect',
      artifact_id: 'artifact-redirect',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-webhook-redirect',
      project_id: 'project-redirect',
      artifact_id: 'artifact-redirect',
      tenant_id: 'tenant-redirect',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-redirect',
        url: 'https://example.com/webhook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-webhook-redirect',
        artifactPath: '/tmp/workspaces/scan-webhook-redirect/source'
      })
    );

    const fetchImpl = vi.fn(() =>
      Promise.resolve({
        ok: false,
        status: 302
      } as Response)
    );

    const { metrics, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: vi.fn(() =>
        Promise.resolve({
          packages: [],
          bom: { bomFormat: 'CycloneDX' },
          licenses: [],
          vulnerabilities: []
        })
      ),
      cleanupWorkspace: vi.fn(() => Promise.resolve()),
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: () => 'failure-id',
      now: () => new Date('2024-01-01T00:00:00.000Z'),
      wait: () => Promise.resolve(),
      webhookRetryAttempts: 1,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await processScanJob(job, dependencies);

    expect(fetchImpl).toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
    const webhookUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(webhookUpdate?.values?.[1]).toMatchObject({ failed: 1 });
  });

  it('reports webhook delivery timeouts as failures after retries', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-timeout',
      project_id: 'project-timeout',
      artifact_id: 'artifact-timeout',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-timeout',
      project_id: 'project-timeout',
      artifact_id: 'artifact-timeout',
      tenant_id: 'tenant-timeout',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-timeout',
        url: 'https://example.com/webhook',
        secret: null,
        events: []
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-timeout',
        artifactPath: '/tmp/workspaces/scan-timeout/source'
      })
    );

    const scannerResult = {
      packages: [],
      bom: { bomFormat: 'CycloneDX', version: 1, components: [] },
      licenses: [],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const abortError = new Error('aborted');
    abortError.name = 'AbortError';

    const fetchImpl = vi.fn((_: string, options?: { signal?: AbortSignal }) =>
      new Promise<Response>((_, reject) => {
        const signal = options?.signal;
        if (signal?.aborted) {
          reject(abortError);
          return;
        }

        signal?.addEventListener('abort', () => reject(abortError));
      })
    );

    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();
    const wait = vi.fn(() => Promise.resolve());
    const nowSequence = [
      new Date('2024-05-03T00:00:00.000Z'),
      new Date('2024-05-03T00:00:05.000Z')
    ];
    const now = vi.fn(() => nowSequence.shift() ?? new Date('2024-05-03T00:00:05.000Z'));

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: vi.fn(() => 'sbom-timeout'),
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    vi.useFakeTimers();
    try {
      const promise = processScanJob(job, dependencies);
      await vi.runAllTimersAsync();
      await promise;
    } finally {
      vi.useRealTimers();
    }

    expect(fetchImpl).toHaveBeenCalledTimes(DEFAULT_WEBHOOK_ATTEMPTS);
    expect(wait).toHaveBeenCalledTimes(DEFAULT_WEBHOOK_ATTEMPTS - 1);
    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'failed' });
    expect(timer).toHaveBeenCalledWith({ status: 'succeeded' });
    expect(lookupMock).toHaveBeenCalledWith('example.com', { all: true });
    const summaryUpdate = queryCalls.find((call) => call.text.includes('jsonb_set'));
    expect(summaryUpdate?.values?.[1]).toMatchObject({ failed: 1 });
  });

  it('rolls back transactional writes when persistence fails', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-rollback',
      project_id: 'project-rollback',
      artifact_id: 'artifact-rollback',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-rollback',
      project_id: 'project-rollback',
      artifact_id: 'artifact-rollback',
      tenant_id: 'tenant-rollback',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [];

    const queryCalls: QueryCall[] = [];
    const dbQuery: DbQueryMock = vi.fn((text: string, values?: unknown[]) => {
      queryCalls.push({ text, values });

      if (text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK') {
        return Promise.resolve({ rows: [] });
      }

      if (text.includes('FROM scans')) {
        return Promise.resolve({ rows: [scanRecord] });
      }

      if (text.includes('FROM webhooks')) {
        return Promise.resolve({ rows: webhooks });
      }

      if (text.includes('INSERT INTO licenses')) {
        return Promise.reject(new Error('licenses insert failed'));
      }

      return Promise.resolve({ rows: [] });
    });

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-rollback',
        artifactPath: '/tmp/workspaces/scan-rollback/source'
      })
    );

    const scannerResult = {
      packages: [
        {
          name: 'pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          purl: 'pkg:npm/pkg@1.0.0'
        }
      ],
      bom: { bomFormat: 'CycloneDX', version: 1, components: [] },
      licenses: [
        {
          path: 'LICENSE',
          spdxId: 'MIT',
          packageName: 'pkg'
        }
      ],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: vi.fn(() => 'sbom-rollback'),
      now: vi.fn(() => new Date('2024-05-04T00:00:00.000Z')),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await expect(processScanJob(job, dependencies)).rejects.toThrow('licenses insert failed');

    expect(queryCalls.some((call) => call.text === 'BEGIN')).toBe(true);
    expect(queryCalls.some((call) => call.text === 'ROLLBACK')).toBe(true);
    expect(queryCalls.some((call) => call.text === 'COMMIT')).toBe(false);
    const failureUpdate = queryCalls.find((call) => call.text.includes('status = $2') && call.values?.[1] === 'failed');
    expect(failureUpdate).toBeDefined();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(webhookOutcomeCounter.inc).not.toHaveBeenCalledWith({ result: 'success' });
    expect(timer).toHaveBeenCalledWith({ status: 'failed' });
  });

  it('aborts the transaction when SBOM persistence fails before downstream writes', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-txn-abort',
      project_id: 'project-txn-abort',
      artifact_id: 'artifact-txn-abort',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-txn-abort',
      project_id: 'project-txn-abort',
      artifact_id: 'artifact-txn-abort',
      tenant_id: 'tenant-txn-abort',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const db: WorkerDependencies['db'] = {
      query: dbQuery,
      async transaction(handler) {
        await dbQuery('BEGIN');
        try {
          const result = await handler({
            query: async (text: string, values?: unknown[]) => {
              const response = await dbQuery(text, values);
              if (text.includes('INSERT INTO sboms')) {
                throw new Error('sbom persistence failed');
              }
              return response;
            }
          });
          await dbQuery('COMMIT');
          return result;
        } catch (error) {
          await dbQuery('ROLLBACK');
          throw error;
        }
      }
    };

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-txn-abort',
        artifactPath: '/tmp/workspaces/scan-txn-abort/source'
      })
    );

    const scannerResult: ScannerResult = {
      packages: [
        {
          name: 'pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          purl: 'pkg:npm/pkg@1.0.0'
        }
      ],
      bom: { bomFormat: 'CycloneDX', version: 1, components: [] },
      licenses: [],
      vulnerabilities: []
    };

    const runScannersMock = vi.fn(() => Promise.resolve(scannerResult));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));
    const { metrics, timer } = createMetricsMocks();

    const dependencies: WorkerDependencies = {
      db,
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: vi.fn(() => 'sbom-txn-abort'),
      now: vi.fn(() => new Date('2024-05-05T00:00:00.000Z')),
      wait: vi.fn(() => Promise.resolve()),
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await expect(processScanJob(job, dependencies)).rejects.toThrow('sbom persistence failed');

    const beginCount = queryCalls.filter((call) => call.text === 'BEGIN').length;
    const rollbackCount = queryCalls.filter((call) => call.text === 'ROLLBACK').length;
    const commitCount = queryCalls.filter((call) => call.text === 'COMMIT').length;
    expect(beginCount).toBeGreaterThan(0);
    expect(rollbackCount).toBeGreaterThan(0);
    expect(commitCount).toBe(0);

    expect(queryCalls.some((call) => call.text.includes('INSERT INTO sboms'))).toBe(true);
    expect(queryCalls.some((call) => call.text.includes('INSERT INTO licenses'))).toBe(false);
    expect(queryCalls.some((call) => call.text.includes('status = $2') && call.values?.[1] === 'succeeded')).toBe(false);
    const failureUpdate = queryCalls.find(
      (call) => call.text.includes('status = $2') && call.values?.[1] === 'failed'
    );
    expect(failureUpdate).toBeDefined();
    expect(timer).toHaveBeenCalledWith({ status: 'failed' });
  });
  it('emits scan.failed webhooks when scanners throw', async () => {
    const job: ScanJobData = {
      scan_id: 'scan-error',
      project_id: 'project-4',
      artifact_id: 'artifact-4',
      policy_id: null
    };

    const scanRecord: ScanRecordRow = {
      scan_id: 'scan-error',
      project_id: 'project-4',
      artifact_id: 'artifact-4',
      tenant_id: 'tenant-4',
      policy_id: null,
      artifact_type: 'git',
      artifact_ref: { url: 'https://example.com/repo.git', commit: 'jkl012' },
      artifact_metadata: {}
    };

    const webhooks: Array<WebhookRow | PlainWebhookRow> = [
      {
        id: 'webhook-4',
        url: 'https://example.com/webhook',
        secret: null,
        events: ['scan.failed']
      }
    ];

    const queryCalls: QueryCall[] = [];
    const dbQuery = createDbQuery(queryCalls, scanRecord, webhooks);

    const fetchArtifactMock = vi.fn(() =>
      Promise.resolve({
        workspacePath: '/tmp/workspaces/scan-error',
        artifactPath: '/tmp/workspaces/scan-error/source'
      })
    );

    const runScannersMock = vi.fn(() => Promise.reject(new Error('scanner failure')));
    const cleanupWorkspaceMock = vi.fn(() => Promise.resolve());
    const fetchImpl = vi.fn(() => Promise.resolve({ ok: true, status: 200 } as unknown as Response));

    const { metrics, timer, webhookOutcomeCounter } = createMetricsMocks();

    const nowSequence = [
      new Date('2024-04-01T00:00:00.000Z'),
      new Date('2024-04-01T00:00:03.000Z'),
      new Date('2024-04-01T00:00:03.000Z')
    ];
    const now = vi.fn(() => {
      const value = nowSequence.shift();
      return value ?? new Date('2024-04-01T00:00:03.000Z');
    });

    const wait = vi.fn(() => Promise.resolve());

    const dependencies: WorkerDependencies = {
      db: createDbAdapter(dbQuery),
      fetchArtifact: fetchArtifactMock,
      runScanners: runScannersMock,
      cleanupWorkspace: cleanupWorkspaceMock,
      metrics,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      generateId: vi.fn(() => 'id'),
      now,
      wait,
      webhookRetryAttempts: DEFAULT_WEBHOOK_ATTEMPTS,
      webhookRetryBaseMs: WEBHOOK_RETRY_BASE_MS,
      webhookSecretKey: TEST_WEBHOOK_SECRET_KEY
    };

    await expect(processScanJob(job, dependencies)).rejects.toThrow('scanner failure');

    const failureUpdate = queryCalls.find((call) => call.text.includes('duration_ms = $5'));
    expect(failureUpdate?.values?.[1]).toBe('failed');
    expect(failureUpdate?.values?.[4]).toBe(3000);
    expect(queryCalls.some((call) => call.text === 'BEGIN')).toBe(false);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const webhookCall = fetchImpl.mock.calls[0];
    const body = (webhookCall?.[1] as { body?: string } | undefined)?.body;
    expect(body).toBeDefined();
    expect(JSON.parse(body as string)).toMatchObject({
      event: 'scan.failed',
      data: { scan_id: 'scan-error', status: 'failed', error: 'scanner failure' }
    });

    expect(webhookOutcomeCounter.inc).toHaveBeenCalledWith({ result: 'success' });
    expect(timer).toHaveBeenCalledWith({ status: 'failed' });
    expect(cleanupWorkspaceMock).toHaveBeenCalledWith('/tmp/workspaces/scan-error');
  });
});

describe('worker license enforcement', () => {
  const originalEnv: Partial<Record<keyof typeof WORKER_ENV_BASE, string | undefined>> = {};
  let originalLicenseKey: string | undefined;

  function createLicenseStatus(
    overrides: Partial<licenseManager.LicenseStatusResult> = {}
  ): licenseManager.LicenseStatusResult {
    return {
      licenseId: 'worker-license',
      status: 'active',
      expiresAt: '2030-01-01T00:00:00.000Z',
      features: ['scan:execute'],
      lastValidatedAt: '2024-06-01T00:00:00.000Z',
      warnings: [],
      ...overrides
    } satisfies licenseManager.LicenseStatusResult;
  }

  beforeEach(() => {
    bullModule.WorkerMock.mockClear();
    originalLicenseKey = process.env.LICENSE_PUBLIC_KEY;
    for (const [key, value] of Object.entries(WORKER_ENV_BASE)) {
      originalEnv[key as keyof typeof WORKER_ENV_BASE] = process.env[key];
      process.env[key] = value;
    }
    process.env.LICENSE_PUBLIC_KEY = TEST_LICENSE_PUBLIC_KEY;
  });

  afterEach(() => {
    for (const key of Object.keys(WORKER_ENV_BASE)) {
      const previous = originalEnv[key as keyof typeof WORKER_ENV_BASE];
      if (previous === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous;
      }
    }
    if (originalLicenseKey === undefined) {
      delete process.env.LICENSE_PUBLIC_KEY;
    } else {
      process.env.LICENSE_PUBLIC_KEY = originalLicenseKey;
    }
    bullModule.WorkerMock.mockClear();
  });

  it('refuses to start when the license is revoked', async () => {
    const licenseStatusProvider = vi.fn().mockResolvedValue(createLicenseStatus({ status: 'revoked' }));

    await expect(
      startWorker({
        licenseStatusProvider
      })
    ).rejects.toThrow(/revoked/i);

    expect(licenseStatusProvider).toHaveBeenCalledTimes(1);
    expect(bullModule.WorkerMock).not.toHaveBeenCalled();
  });

  it('refuses to start when the license lacks scan entitlement', async () => {
    const licenseStatusProvider = vi.fn().mockResolvedValue(createLicenseStatus({ features: [] }));

    await expect(
      startWorker({
        licenseStatusProvider
      })
    ).rejects.toThrow(/scan:execute/i);

    expect(licenseStatusProvider).toHaveBeenCalledTimes(1);
    expect(bullModule.WorkerMock).not.toHaveBeenCalled();
  });

  it('rejects startup when the license public key is not base64url encoded', async () => {
    const previous = process.env.LICENSE_PUBLIC_KEY;
    process.env.LICENSE_PUBLIC_KEY = 'invalid key';

    const getLicenseStatusSpy = vi.spyOn(licenseManager, 'getLicenseStatus');
    const { metrics } = createMetricsMocks();
    const connection = { quit: vi.fn() } as unknown as Redis;

    await expect(
      startWorker({
        connection,
        metrics,
        db: __testCreateDatabase('postgres://localhost:5432/app')
      })
    ).rejects.toThrow(/LICENSE_PUBLIC_KEY must be a base64url-encoded DER public key string/i);

    expect(getLicenseStatusSpy).not.toHaveBeenCalled();
    getLicenseStatusSpy.mockRestore();

    if (previous === undefined) {
      delete process.env.LICENSE_PUBLIC_KEY;
    } else {
      process.env.LICENSE_PUBLIC_KEY = previous;
    }
  });

  it('rejects startup when the license public key has an invalid length', async () => {
    const previous = process.env.LICENSE_PUBLIC_KEY;
    process.env.LICENSE_PUBLIC_KEY = Buffer.from([0x30]).toString('base64url');

    const getLicenseStatusSpy = vi.spyOn(licenseManager, 'getLicenseStatus');
    const { metrics } = createMetricsMocks();
    const connection = { quit: vi.fn() } as unknown as Redis;

    await expect(
      startWorker({
        connection,
        metrics,
        db: __testCreateDatabase('postgres://localhost:5432/app')
      })
    ).rejects.toThrow(/LICENSE_PUBLIC_KEY must decode to a 44 byte Ed25519 public key/i);

    expect(getLicenseStatusSpy).not.toHaveBeenCalled();
    getLicenseStatusSpy.mockRestore();

    if (previous === undefined) {
      delete process.env.LICENSE_PUBLIC_KEY;
    } else {
      process.env.LICENSE_PUBLIC_KEY = previous;
    }
  });

  it('starts the worker when the license is active and entitled', async () => {
    const licenseStatusProvider = vi.fn().mockResolvedValue(createLicenseStatus());
    const { metrics } = createMetricsMocks();
    const connection = { quit: vi.fn() } as unknown as Redis;

    const worker = await startWorker({
      licenseStatusProvider,
      connection,
      metrics,
      db: __testCreateDatabase('postgres://localhost:5432/app')
    });

    expect(licenseStatusProvider).toHaveBeenCalledTimes(1);
    expect(bullModule.WorkerMock).toHaveBeenCalledTimes(1);
    expect(worker).toBeDefined();
  });

  it('passes the configured license public key to the default status provider', async () => {
    const previous = process.env.LICENSE_PUBLIC_KEY;
    process.env.LICENSE_PUBLIC_KEY = DIFFERENT_LICENSE_PUBLIC_KEY;
    secretsSendMock.mockReset();

    const getLicenseStatusSpy = vi
      .spyOn(licenseManager, 'getLicenseStatus')
      .mockResolvedValue(createLicenseStatus());

    const { metrics } = createMetricsMocks();
    const connection = { quit: vi.fn() } as unknown as Redis;

    try {
      const worker = await startWorker({
        connection,
        metrics,
        db: __testCreateDatabase('postgres://localhost:5432/app')
      });

      expect(getLicenseStatusSpy).toHaveBeenCalledWith(
        expect.objectContaining({ publicKey: DIFFERENT_LICENSE_PUBLIC_KEY })
      );

      await worker.close();
    } finally {
      getLicenseStatusSpy.mockRestore();
      if (previous === undefined) {
        delete process.env.LICENSE_PUBLIC_KEY;
      } else {
        process.env.LICENSE_PUBLIC_KEY = previous;
      }
    }
  });

  it('resolves secretsmanager license keys before validating', async () => {
    const previous = process.env.LICENSE_PUBLIC_KEY;
    process.env.LICENSE_PUBLIC_KEY = 'secretsmanager://prod/license-key';
    secretsSendMock.mockReset();
    secretsSendMock.mockResolvedValueOnce({ SecretString: RESOLVED_SECRET_LICENSE_PUBLIC_KEY });

    const getLicenseStatusSpy = vi
      .spyOn(licenseManager, 'getLicenseStatus')
      .mockResolvedValue(createLicenseStatus());

    const { metrics } = createMetricsMocks();
    const connection = { quit: vi.fn() } as unknown as Redis;

    try {
      const worker = await startWorker({
        connection,
        metrics,
        db: __testCreateDatabase('postgres://localhost:5432/app')
      });

      const secretCall = secretsSendMock.mock.calls.at(-1)?.[0];
      expect(secretCall).toBeInstanceOf(secretsModule.GetSecretValueCommandMock);
      expect((secretCall as { input: { SecretId: string } }).input).toEqual(
        expect.objectContaining({ SecretId: 'prod/license-key' })
      );
      expect(getLicenseStatusSpy).toHaveBeenCalledWith(
        expect.objectContaining({ publicKey: RESOLVED_SECRET_LICENSE_PUBLIC_KEY })
      );

      await worker.close();
    } finally {
      getLicenseStatusSpy.mockRestore();
      if (previous === undefined) {
        delete process.env.LICENSE_PUBLIC_KEY;
      } else {
        process.env.LICENSE_PUBLIC_KEY = previous;
      }
      __testResetWorkerSecretCache();
    }
  });
});
