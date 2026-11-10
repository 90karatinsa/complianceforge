// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildServer, type Database, type JobQueue, type RedisConnection } from '../api/src/server.ts';
import type { Metrics } from '../metrics/index.ts';
import { createLicenseStatusProvider } from './helpers/license.ts';
import { TEST_API_KEY_SALT } from './helpers/auth.ts';
import { createTracer } from '../observability/tracing.ts';
import { processScanJob, __testDeliverWebhook } from '../worker/src/worker.ts';

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
    send = vi.fn();
  },
  GetSecretValueCommand: class {}
}));

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(() => Promise.resolve([{ address: '203.0.113.1', family: 4 }]))
}));

vi.mock('undici', () => {
  return {
    Agent: vi.fn(() => ({
      dispatch: vi.fn(),
      close: vi.fn(() => Promise.resolve()),
      destroy: vi.fn(() => Promise.resolve())
    }))
  };
});

describe('observability instrumentation', () => {
  let metrics: Metrics;

  beforeEach(() => {
    metrics = {
      registry: {
        metrics: () => Promise.resolve(''),
        contentType: 'text/plain'
      },
      queueDepthGauge: {
        set: () => {}
      },
      scanDurationHistogram: {
        startTimer: () => () => {}
      },
      noticeBuildHistogram: {
        startTimer: () => () => {}
      },
      webhookOutcomeCounter: {
        inc: () => {}
      },
      feedImportCounter: {
        inc: () => {}
      },
      vexStateGauge: {
        set: () => {}
      },
      vexNoiseGauge: {
        set: () => {}
      },
      vexDowngradedCounter: {
        inc: () => {}
      },
      purgeDurationHistogram: {
        startTimer: () => () => {}
      }
    } satisfies Metrics;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('attaches trace headers and records request spans for API calls when telemetry is enabled', async () => {
    const tracer = createTracer('test-api', { enabled: true });
    const probeSpan = tracer.startSpan('probe');
    expect(probeSpan.context.sampled).toBe(true);
    probeSpan.end();
    const db: Database = {
      query: vi.fn(async (text: string) => {
        if (text.includes('SELECT 1')) {
          return { rows: [{ '?column?': 1 }] };
        }
        if (text.includes('MAX(completed_at)')) {
          return { rows: [{ last_scan_at: '2024-01-01T00:00:00.000Z' }] };
        }
        if (text.includes('FROM feed_manifests')) {
          return { rows: [{ version: 'feed-test' }] };
        }
        if (text.includes('FROM vex_statements')) {
          return { rows: [{ total: 0 }] };
        }
        return { rows: [] };
      })
    };

    const queue: JobQueue = {
      add: vi.fn(),
      getJobCounts: vi.fn(() =>
        Promise.resolve({ waiting: 1, active: 0, delayed: 0, completed: 0, failed: 0 })
      )
    } as JobQueue;

    const redis: RedisConnection = {
      ping: vi.fn(() => Promise.resolve('PONG'))
    };

    const app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: async () => null,
      licenseStatusProvider: createLicenseStatusProvider(),
      tracer,
      telemetryEnabled: true
    });

    const response = await app.inject({ method: 'GET', url: '/v1/health' });

    expect(response.statusCode).toBe(200);
    expect(response.headers).toHaveProperty('traceparent');

    const spans = tracer.getFinishedSpans();
    const requestSpan = spans.find((span) => span.name === 'http.request');
    expect(requestSpan).toBeDefined();
    expect(requestSpan?.status).toBe('ok');
    expect(requestSpan?.attributes['http.method']).toBe('GET');
    expect(requestSpan?.attributes['http.status_code']).toBe(200);

    await app.close();
  });

  it('omits spans and headers when telemetry is disabled', async () => {
    const tracer = createTracer('test-api', { enabled: false });
    const db: Database = {
      query: vi.fn(async (text: string) => {
        if (text.includes('SELECT 1')) {
          return { rows: [{ '?column?': 1 }] };
        }
        if (text.includes('MAX(completed_at)')) {
          return { rows: [{ last_scan_at: '2024-01-01T00:00:00.000Z' }] };
        }
        if (text.includes('FROM feed_manifests')) {
          return { rows: [{ version: 'feed-test' }] };
        }
        if (text.includes('FROM vex_statements')) {
          return { rows: [{ total: 0 }] };
        }
        return { rows: [] };
      })
    };

    const queue: JobQueue = {
      add: vi.fn(),
      getJobCounts: vi.fn(() =>
        Promise.resolve({ waiting: 1, active: 0, delayed: 0, completed: 0, failed: 0 })
      )
    } as JobQueue;

    const redis: RedisConnection = {
      ping: vi.fn(() => Promise.resolve('PONG'))
    };

    const app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: async () => null,
      licenseStatusProvider: createLicenseStatusProvider(),
      tracer,
      telemetryEnabled: false
    });

    const response = await app.inject({ method: 'GET', url: '/v1/health' });

    expect(response.statusCode).toBe(200);
    expect(response.headers).not.toHaveProperty('traceparent');
    expect(tracer.getFinishedSpans()).toHaveLength(0);

    await app.close();
  });

  it('defaults to a no-op tracer when telemetry opt-in is not provided', async () => {
    const tracer = createTracer('test-api');
    const db: Database = {
      query: vi.fn(async (text: string) => {
        if (text.includes('SELECT 1')) {
          return { rows: [{ '?column?': 1 }] };
        }
        if (text.includes('MAX(completed_at)')) {
          return { rows: [{ last_scan_at: '2024-01-01T00:00:00.000Z' }] };
        }
        if (text.includes('FROM feed_manifests')) {
          return { rows: [{ version: 'feed-test' }] };
        }
        if (text.includes('FROM vex_statements')) {
          return { rows: [{ total: 0 }] };
        }
        return { rows: [] };
      })
    };

    const queue: JobQueue = {
      add: vi.fn(),
      getJobCounts: vi.fn(() =>
        Promise.resolve({ waiting: 1, active: 0, delayed: 0, completed: 0, failed: 0 })
      )
    } as JobQueue;

    const redis: RedisConnection = {
      ping: vi.fn(() => Promise.resolve('PONG'))
    };

    const app = await buildServer({
      version: '0.0.0-test',
      db,
      queue,
      redis,
      metrics,
      apiKeySalt: TEST_API_KEY_SALT,
      lookupApiKey: async () => null,
      licenseStatusProvider: createLicenseStatusProvider(),
      tracer
    });

    const response = await app.inject({ method: 'GET', url: '/v1/health' });

    expect(response.statusCode).toBe(200);
    expect(response.headers).not.toHaveProperty('traceparent');
    expect(tracer.getFinishedSpans()).toHaveLength(0);

    await app.close();
  });

  it('emits worker spans for scan processing', async () => {
    const tracer = createTracer('test-worker', { enabled: true });
    const warmupSpan = tracer.startSpan('warmup');
    expect(warmupSpan.context.sampled).toBe(true);
    warmupSpan.end();
    let idCounter = 0;
    const generateId = () => `id-${++idCounter}`;
    let nowCounter = 0;
    const now = () => new Date(1704067200000 + nowCounter++ * 1000);

    const dbQuery = vi.fn(async (text: string) => {
      if (text.includes('UPDATE scans SET status = $2')) {
        return { rows: [] };
      }
      if (text.includes('FROM scans s')) {
        return {
          rows: [
            {
              scan_id: 'scan-1',
              project_id: 'project-1',
              artifact_id: 'artifact-1',
              tenant_id: 'tenant-1',
              policy_id: null,
              artifact_type: 'git',
              artifact_ref: { url: 'https://example.com/repo.git' },
              artifact_metadata: null
            }
          ]
        };
      }
      if (text.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: {} }] };
      }
      if (text.includes('FROM webhooks')) {
        return { rows: [] };
      }
      if (text.includes('jsonb_set')) {
        return { rows: [] };
      }
      if (text.includes('INSERT INTO evidence_packs')) {
        return { rows: [] };
      }
      return { rows: [] };
    });

    const transactionQuery = vi.fn(async (text: string) => {
      if (text.includes('policy_exceptions')) {
        return { rows: [] };
      }
      if (text.includes('vex_statements')) {
        return { rows: [] };
      }
      return { rows: [] };
    });

    const db: Database = {
      query: dbQuery,
      transaction: vi.fn(async (handler) => handler({ query: transactionQuery }))
    };

    const workerMetrics: Metrics = {
      ...metrics,
      webhookOutcomeCounter: {
        inc: () => {}
      }
    };

    const dependencies = {
      db,
      fetchArtifact: vi.fn(async () => ({
        artifactPath: '/tmp/workspace',
        workspacePath: '/tmp/workspace'
      })),
      runScanners: vi.fn(async () => ({
        packages: [],
        bom: {
          bomFormat: 'CycloneDX' as const,
          specVersion: '1.5' as const,
          version: 1,
          metadata: { timestamp: now().toISOString(), tools: [] },
          components: []
        },
        licenses: [],
        vulnerabilities: []
      })),
      cleanupWorkspace: vi.fn(() => Promise.resolve()),
      buildEvidencePack: vi.fn(async () => ({
        manifest: {},
        signature: null,
        hashAlgorithm: 'sha256'
      })),
      metrics: workerMetrics,
      fetchImpl: vi.fn() as unknown as typeof fetch,
      generateId,
      now,
      wait: async () => {},
      webhookRetryAttempts: 1,
      webhookRetryBaseMs: 10,
      tracer
    };

    const job = {
      scan_id: 'scan-1',
      project_id: 'project-1',
      artifact_id: 'artifact-1',
      policy_id: null
    } as const;

    await processScanJob(job, dependencies);

    const spans = tracer.getFinishedSpans();
    const spanNames = spans.map((span) => span.name);
    expect(spanNames).toEqual(
      expect.arrayContaining([
        'worker.process_scan',
        'worker.fetch_artifact',
        'worker.run_scanners',
        'worker.persist_results'
      ])
    );

    const persistSpan = spans.find((span) => span.name === 'worker.persist_results');
    expect(persistSpan?.status).toBe('ok');
    const rootSpan = spans.find((span) => span.name === 'worker.process_scan');
    expect(rootSpan?.status).toBe('ok');
  });

  it('propagates trace context to webhook deliveries', async () => {
    const tracer = createTracer('test-worker', { enabled: true });
    const primingSpan = tracer.startSpan('priming');
    expect(primingSpan.context.sampled).toBe(true);
    primingSpan.end();
    const fetchMock = vi
      .fn<Promise<Response>, Parameters<typeof fetch>>()
      .mockResolvedValue({ ok: true, status: 200 } as unknown as Response);

    const metricsStub: Metrics = {
      ...metrics,
      webhookOutcomeCounter: {
        inc: vi.fn()
      }
    };

    const dependencies = {
      db: {
        query: vi.fn(async () => ({ rows: [] })),
        transaction: vi.fn(async () => ({}))
      },
      fetchArtifact: vi.fn(),
      runScanners: vi.fn(),
      cleanupWorkspace: vi.fn(),
      metrics: metricsStub,
      fetchImpl: fetchMock as unknown as typeof fetch,
      generateId: () => 'id-1',
      now: () => new Date('2024-01-01T00:00:00.000Z'),
      wait: async () => {},
      webhookRetryAttempts: 1,
      webhookRetryBaseMs: 10,
      tracer
    } as unknown as Parameters<typeof __testDeliverWebhook>[3];

    const parentSpan = tracer.startSpan('worker.process_scan');

    const result = await __testDeliverWebhook(
      {
        id: 'webhook-1',
        url: 'https://example.com/hook',
        secret: null,
        events: null
      } as unknown as Parameters<typeof __testDeliverWebhook>[0],
      'scan.completed',
      { event: 'scan.completed' },
      dependencies,
      parentSpan.context
    );

    parentSpan.end();

    expect(result).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const headers = (fetchMock.mock.calls[0]?.[1] as { headers?: Record<string, string> } | undefined)?.headers;
    expect(headers).toBeDefined();
    expect(headers).toHaveProperty('traceparent');

    const spans = tracer.getFinishedSpans();
    const webhookSpan = spans.find((span) => span.name === 'worker.deliver_webhook');
    expect(webhookSpan?.status).toBe('ok');
  });

  it('skips worker spans when telemetry is disabled', async () => {
    const tracer = createTracer('test-worker', { enabled: false });
    const metricsStub: Metrics = {
      ...metrics,
      webhookOutcomeCounter: {
        inc: () => {}
      }
    };

    const dbQuery = vi.fn(async (text: string) => {
      if (text.includes('UPDATE scans SET status = $2')) {
        return { rows: [] };
      }
      if (text.includes('FROM scans s')) {
        return {
          rows: [
            {
              scan_id: 'scan-telemetry-disabled',
              project_id: 'project-1',
              artifact_id: 'artifact-1',
              tenant_id: 'tenant-1',
              policy_id: null,
              artifact_type: 'git',
              artifact_ref: { url: 'https://example.com/repo.git' },
              artifact_metadata: null
            }
          ]
        };
      }
      if (text.includes('SELECT metadata FROM tenants')) {
        return { rows: [{ metadata: {} }] };
      }
      if (text.includes('FROM webhooks')) {
        return { rows: [] };
      }
      if (text.includes('jsonb_set')) {
        return { rows: [] };
      }
      if (text.includes('INSERT INTO evidence_packs')) {
        return { rows: [] };
      }
      if (text.includes('INSERT INTO scan_events')) {
        return { rows: [] };
      }
      return { rows: [] };
    });

    const transactionQuery = vi.fn(async (text: string) => {
      if (text.includes('policy_exceptions')) {
        return { rows: [] };
      }
      if (text.includes('vex_statements')) {
        return { rows: [] };
      }
      return { rows: [] };
    });

    const db: Database = {
      query: dbQuery,
      transaction: vi.fn(async (handler) => handler({ query: transactionQuery }))
    };

    const dependencies = {
      db,
      fetchArtifact: vi.fn(async () => ({
        artifactPath: '/tmp/workspace',
        workspacePath: '/tmp/workspace'
      })),
      runScanners: vi.fn(async () => ({
        packages: [],
        bom: {
          bomFormat: 'CycloneDX' as const,
          specVersion: '1.5' as const,
          version: 1,
          metadata: { timestamp: new Date().toISOString(), tools: [] },
          components: []
        },
        licenses: [],
        vulnerabilities: []
      })),
      cleanupWorkspace: vi.fn(async () => {}),
      buildEvidencePack: vi.fn(async () => ({
        manifest: {},
        signature: null,
        hashAlgorithm: 'sha256'
      })),
      metrics: metricsStub,
      fetchImpl: vi.fn() as unknown as typeof fetch,
      generateId: () => 'id-1',
      now: () => new Date('2024-01-01T00:00:00.000Z'),
      wait: async () => {},
      webhookRetryAttempts: 1,
      webhookRetryBaseMs: 10,
      tracer
    } satisfies Parameters<typeof processScanJob>[1];

    await processScanJob(
      { scan_id: 'scan-telemetry-disabled', project_id: 'project-1', artifact_id: 'artifact-1', policy_id: null },
      dependencies
    );

    expect(tracer.getFinishedSpans()).toHaveLength(0);
  });
});
