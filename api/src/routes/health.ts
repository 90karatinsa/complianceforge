// SPDX-License-Identifier: MIT

import { FastifyInstance } from 'fastify';
import type { Database, JobQueue, RedisConnection } from '../server.js';
import type { Metrics } from '../../../metrics/index.js';

interface HealthRouteOptions {
  readonly version: string;
  readonly db: Database;
  readonly queue: JobQueue;
  readonly redis: RedisConnection;
  readonly metrics: Metrics;
}

interface QueueCounts {
  waiting: number;
  active: number;
  delayed: number;
}

type HealthStatus = 'healthy' | 'degraded' | 'down';

function toIsoString(value: Date | string | null | undefined): string | null {
  if (!value) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function deriveSignatureStatus(signature: string | null, verifiedAt: Date | string | null): string | null {
  if (!signature) {
    return null;
  }

  if (verifiedAt) {
    return 'İmza doğrulandı';
  }

  return 'İmza doğrulanamadı';
}

function deriveHealthStatus(
  dependencies: Record<'db' | 'redis' | 'bull', 'ok' | 'error'>
): HealthStatus {
  if (dependencies.db === 'error') {
    return 'down';
  }

  if (dependencies.redis === 'error' || dependencies.bull === 'error') {
    return 'degraded';
  }

  return 'healthy';
}

export function registerHealthRoute(app: FastifyInstance, options: HealthRouteOptions): void {
  const healthSchema = {
    type: 'object',
    properties: {
      status: { type: 'string' },
      version: { type: 'string' },
      uptime_s: { type: 'number' },
      dependencies: {
        type: 'object',
        properties: {
          db: { type: 'string' },
          redis: { type: 'string' },
          bull: { type: 'string' }
        },
        required: ['db', 'redis', 'bull']
      },
      queue: {
        type: 'object',
        properties: {
          waiting: { type: 'number' },
          active: { type: 'number' },
          delayed: { type: 'number' }
        },
        required: ['waiting', 'active', 'delayed']
      },
      last_scan_at: { type: ['string', 'null'], nullable: true },
      feeds: {
        type: 'object',
        properties: {
          active_version: { type: ['string', 'null'], nullable: true },
          last_imported_at: { type: ['string', 'null'], nullable: true },
          signature_status: { type: ['string', 'null'], nullable: true }
        },
        required: ['active_version', 'last_imported_at', 'signature_status']
      },
      vex: {
        type: 'object',
        properties: {
          total: { type: 'number' }
        },
        required: ['total']
      },
      worker_capacity: { type: ['number', 'null'], nullable: true },
      slo: {
        type: 'object',
        properties: {
          summary_p95_ms: { type: 'number' },
          orchestration_p95_ms: { type: 'number' }
        },
        required: ['summary_p95_ms', 'orchestration_p95_ms']
      },
      last_failures: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            occurred_at: { type: 'string' },
            message: { type: 'string' }
          },
          required: ['occurred_at', 'message']
        }
      },
      details: {
        type: 'object',
        properties: {
          summary: { type: 'string' }
        },
        required: ['summary']
      }
    },
    required: [
      'status',
      'version',
      'uptime_s',
      'dependencies',
      'queue',
      'last_scan_at',
      'feeds',
      'vex',
      'worker_capacity',
      'slo',
      'last_failures',
      'details'
    ]
  } as const;

  app.get('/v1/health', {
    schema: {
      response: {
        200: healthSchema,
        503: healthSchema
      }
    }
  }, async (_request, reply) => {
    const dependencies: Record<'db' | 'redis' | 'bull', 'ok' | 'error'> = {
      db: 'ok',
      redis: 'ok',
      bull: 'ok'
    };

    let queueCounts: QueueCounts = { waiting: 0, active: 0, delayed: 0 };
    let lastScanAt: string | null = null;
    let activeFeedVersion: string | null = null;
    let feedImportedAt: string | null = null;
    let feedSignatureStatus: string | null = null;
    let vexTotal = 0;
    let workerCapacity: number | null = null;
    let summaryP95Ms = 0;
    let orchestrationP95Ms = 0;
    let recentFailures: Array<{ occurred_at: string; message: string }> = [];
    let detailSummary = 'Platform bileşenleri sağlıklı.';

    try {
      await options.db.query('SELECT 1');
    } catch (error) {
      dependencies.db = 'error';
      app.log.error({ err: error }, 'Database health check failed');
    }

    try {
      const counts = await options.queue.getJobCounts?.();
      if (counts) {
        queueCounts = {
          waiting: counts.waiting ?? 0,
          active: counts.active ?? 0,
          delayed: counts.delayed ?? 0
        };
      }
    } catch (error) {
      dependencies.bull = 'error';
      app.log.error({ err: error }, 'Queue health check failed');
    }

    try {
      await options.redis.ping();
    } catch (error) {
      dependencies.redis = 'error';
      app.log.error({ err: error }, 'Redis health check failed');
    }

    if (dependencies.db === 'ok') {
      const loadLastScan = options.db
        .query<{ last_scan_at: Date | string | null }>('SELECT MAX(completed_at) AS last_scan_at FROM scans')
        .then((result) => {
          const value = result.rows[0]?.last_scan_at ?? null;
          lastScanAt = value ? new Date(value).toISOString() : null;
        })
        .catch((error) => {
          app.log.error({ err: error }, 'Failed to load last scan timestamp');
        });

      const loadFeed = options.db
        .query<{
          active_version: string | null;
          resolved_active_version: string | null;
          active_imported_at: Date | string | null;
          active_verified_at: Date | string | null;
          active_signature: string | null;
          latest_version: string | null;
          latest_imported_at: Date | string | null;
          latest_verified_at: Date | string | null;
          latest_signature: string | null;
        }>(
          `SELECT
             t.metadata->>'active_feed_version' AS active_version,
             fm.version AS resolved_active_version,
             fm.imported_at   AS active_imported_at,
             fm.verified_at   AS active_verified_at,
             fm.signature     AS active_signature,
             latest.version   AS latest_version,
             latest.imported_at AS latest_imported_at,
             latest.verified_at AS latest_verified_at,
             latest.signature AS latest_signature
            FROM tenants t
            LEFT JOIN feed_manifests fm
              ON fm.tenant_id = t.id
             AND fm.version = t.metadata->>'active_feed_version'
            LEFT JOIN LATERAL (
              SELECT version, imported_at, verified_at, signature
                FROM feed_manifests lf
               WHERE lf.tenant_id = t.id
               ORDER BY imported_at DESC
               LIMIT 1
            ) AS latest ON true
           ORDER BY t.created_at ASC
           LIMIT 1`
        )
        .then((feedResult) => {
          const row = feedResult.rows[0];

          if (row) {
            const metadataVersion = typeof row.active_version === 'string' ? row.active_version : null;
            const resolvedActiveVersion = row.resolved_active_version ?? null;
            const latestVersion = row.latest_version ?? null;

            activeFeedVersion = resolvedActiveVersion ?? metadataVersion ?? latestVersion ?? null;

            const activeImportedAt = toIsoString(row.active_imported_at);
            const latestImportedAt = toIsoString(row.latest_imported_at);
            feedImportedAt = latestImportedAt ?? activeImportedAt;

            const signature = row.latest_signature ?? row.active_signature ?? null;
            const verifiedAt = row.latest_verified_at ?? row.active_verified_at ?? null;
            feedSignatureStatus = deriveSignatureStatus(signature, verifiedAt);
          }
        })
        .catch((error) => {
          app.log.error({ err: error }, 'Failed to load feed metadata');
        });

      const loadVexTotals = options.db
        .query<{ total: number }>('SELECT COUNT(*)::int AS total FROM vex_statements')
        .then((vexResult) => {
          vexTotal = vexResult.rows[0]?.total ?? 0;
        })
        .catch((error) => {
          app.log.error({ err: error }, 'Failed to load VEX totals');
        });

      const loadSloMetrics = options.db
        .query<{ summary_p95_ms: number | null; orchestration_p95_ms: number | null; worker_capacity: number | null }>(
          'SELECT summary_p95_ms, orchestration_p95_ms, worker_capacity FROM health_slo_metrics ORDER BY captured_at DESC LIMIT 1'
        )
        .then((sloResult) => {
          if (sloResult.rows[0]) {
            summaryP95Ms = sloResult.rows[0].summary_p95_ms ?? 0;
            orchestrationP95Ms = sloResult.rows[0].orchestration_p95_ms ?? 0;
            workerCapacity = sloResult.rows[0].worker_capacity ?? null;
          }
        })
        .catch((error) => {
          app.log.error({ err: error }, 'Failed to load SLO metrics');
        });

      const loadRecentFailures = options.db
        .query<{ occurred_at: Date | string; message: string }>(
          'SELECT occurred_at, message FROM system_failures ORDER BY occurred_at DESC LIMIT 10'
        )
        .then((failureResult) => {
          recentFailures = failureResult.rows.map((row) => ({
            occurred_at: new Date(row.occurred_at).toISOString(),
            message: row.message
          }));
        })
        .catch((error) => {
          app.log.error({ err: error }, 'Failed to load recent failures');
        });

      await Promise.all([loadLastScan, loadFeed, loadVexTotals, loadSloMetrics, loadRecentFailures]);
    }

    options.metrics.queueDepthGauge.set('waiting', queueCounts.waiting);
    options.metrics.queueDepthGauge.set('active', queueCounts.active);
    options.metrics.queueDepthGauge.set('delayed', queueCounts.delayed);

    const status = deriveHealthStatus(dependencies);
    const responseStatusCode = status === 'healthy' ? 200 : 503;

    if (status === 'down') {
      detailSummary = 'Veritabanı bağlantısı başarısız.';
    } else if (status === 'degraded') {
      detailSummary = 'Kuyruk veya cache servisi yanıt vermiyor.';
    }

    return reply.status(responseStatusCode).send({
      status,
      version: options.version,
      uptime_s: process.uptime(),
      dependencies,
      queue: queueCounts,
      last_scan_at: lastScanAt,
      feeds: {
        active_version: activeFeedVersion,
        last_imported_at: feedImportedAt,
        signature_status: feedSignatureStatus
      },
      vex: {
        total: vexTotal
      },
      worker_capacity: workerCapacity,
      slo: {
        summary_p95_ms: summaryP95Ms,
        orchestration_p95_ms: orchestrationP95Ms
      },
      last_failures: recentFailures,
      details: {
        summary: detailSummary
      }
    });
  });

  app.get('/metrics', async (_request, reply) => {
    const body = await options.metrics.registry.metrics();
    void reply.header('content-type', options.metrics.registry.contentType);
    return reply.send(body);
  });
}
