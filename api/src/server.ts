// SPDX-License-Identifier: MIT

import Fastify, {
  FastifyError,
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  type FastifyServerOptions
} from 'fastify';
import pino, { type LoggerOptions as PinoLoggerOptions } from 'pino';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { Buffer } from 'node:buffer';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { Queue } from 'bullmq';
import Redis from 'ioredis';
import { z, ZodError } from 'zod';
import argon2 from 'argon2';
import { registerHealthRoute } from './routes/health.js';
import { metrics as defaultMetrics, type Metrics } from '../../metrics/index.js';
import { getLicenseStatus, type LicenseStatusResult } from '../../scripts/license-manager.ts';
import { validateLicensePublicKey } from '../../scripts/license-public-key.ts';
import {
  parseFeedManifest,
  verifyFeedSignature,
  FeedArchiveTooLargeError
} from '../../scripts/feed-manifest.ts';
import { encryptWebhookSecret } from '../../worker/src/webhook-crypto.js';
import {
  normalizeImportedSbom,
  buildScannerResultFromImport,
  hashSbomDocument
} from '../../worker/src/sbom-import.js';
import { deriveLicenseObligations } from '../../worker/src/license-obligations.js';
import { evaluatePolicy as evaluatePolicyWithOpa, type PolicyRules } from '../../worker/src/policy-opa.js';
import { buildEvidencePack } from '../../worker/src/evidence-pack.js';
import { createTracer, type SpanHandle, type Tracer } from '../../observability/tracing.js';
import { recordUpdateLogEntry } from '../../observability/update-log.ts';

type Role = 'Admin' | 'Security' | 'Legal' | 'Developer' | 'Auditor';

interface AuthContext {
  apiKeyId: string;
  tenantId: string;
  roles: Role[];
}

interface ApiKeyRecord {
  id: string;
  tenant_id: string;
  permissions: unknown;
  token_hash: string;
  token_lookup_hash?: string | null;
  name?: string;
  created_at?: Date | string;
  last_used_at?: Date | string | null;
}

interface SsoResult {
  tenantId: string;
  apiKeyId: string;
  roles: Role[];
  subject: string;
}

type SsoHandler = (input: {
  request: FastifyRequest;
  payload: unknown;
}) => Promise<SsoResult>;

interface SsoHandlerConfig {
  saml?: SsoHandler;
  oidc?: SsoHandler;
}

declare module 'fastify' {
  interface FastifyRequest {
    authContext?: AuthContext;
  }
}

export interface DatabaseClient {
  query<T = unknown>(text: string, values?: ReadonlyArray<unknown>): Promise<{ rows: T[] }>;
}

export interface Database extends DatabaseClient {
  transaction?<T>(handler: (client: DatabaseClient) => Promise<T>): Promise<T>;
}

export interface JobQueue {
  add<T = unknown>(name: string, payload: T): Promise<unknown>;
  getJobCounts?: () => Promise<Record<string, number>>;
}

export interface RedisConnection {
  ping(): Promise<string>;
}

export interface BuildServerOptions {
  readonly version: string;
  readonly db: Database;
  readonly queue: JobQueue;
  readonly generateId?: () => string;
  readonly redis: RedisConnection;
  readonly metrics?: Metrics;
  readonly apiKeySalt?: string;
  readonly lookupApiKey?: (tokenHash: string) => Promise<ApiKeyRecord | null>;
  readonly rateLimiter?: RateLimiter;
  readonly licenseStatusProvider?: () => Promise<LicenseStatusResult>;
  readonly licensePublicKey?: string;
  readonly feedPublicKey?: string;
  readonly ssoHandlers?: SsoHandlerConfig;
  readonly tracer?: Tracer;
  readonly telemetryEnabled?: boolean;
  readonly logger?: FastifyServerOptions['logger'];
  readonly logDestination?: NodeJS.WritableStream;
  readonly loadHealthPanelHtml?: () => Promise<string>;
  readonly webhookSecretKey?: Buffer;
}

async function runInTransaction<T>(
  db: Database,
  handler: (client: DatabaseClient) => Promise<T>
): Promise<T> {
  if (typeof db.transaction === 'function') {
    return db.transaction((client) => handler(client));
  }

  const transactionalClient: DatabaseClient = {
    query: (text, values) => db.query(text, values)
  };

  await db.query('BEGIN');

  try {
    const result = await handler(transactionalClient);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await db.query('ROLLBACK');
    } catch {
      // ignore rollback failure in fallback mode
    }
    throw error;
  }
}

function compareVersionStrings(a: string, b: string): number {
  const tokenize = (value: string): number[] =>
    value
      .split(/[^0-9]+/gu)
      .filter((segment) => segment.length > 0)
      .map((segment) => Number.parseInt(segment, 10))
      .filter((value) => Number.isFinite(value));

  const aTokens = tokenize(a);
  const bTokens = tokenize(b);
  const length = Math.max(aTokens.length, bTokens.length);

  for (let index = 0; index < length; index += 1) {
    const aValue = aTokens[index] ?? 0;
    const bValue = bTokens[index] ?? 0;

    if (aValue > bValue) {
      return 1;
    }

    if (aValue < bValue) {
      return -1;
    }
  }

  if (a > b) {
    return 1;
  }

  if (a < b) {
    return -1;
  }

  return 0;
}

export interface ApiRuntimeConfig {
  readonly databaseUrl: string;
  readonly redisUrl: string;
  readonly apiKeySalt: string;
  readonly licensePublicKey: string;
  readonly maxConcurrency: number;
  readonly scanTimeoutSeconds: number;
  readonly webhookMaxRetry: number;
  readonly prometheusPort: number;
  readonly scanQueueName: string;
  readonly telemetryEnabled: boolean;
  readonly webhookSecretKey: Buffer;
}

type EnvSource = Record<string, string | undefined>;

const SENSITIVE_HEADER_NAMES = [
  'authorization',
  'proxy-authorization',
  'x-forwarded-authorization',
  'x-api-key',
  'api-key',
  'x-session-token',
  'x-aws-security-token',
  'x-amz-security-token',
  'x-idempotency-key',
  'idempotency-key',
  'x-csrf-token',
  'x-xsrf-token',
  'cookie',
  'set-cookie'
] as const;

const FASTIFY_LOG_REDACT_PATHS = [
  ...SENSITIVE_HEADER_NAMES.map((name) =>
    /^[A-Za-z0-9_]+$/.test(name) ? `req.headers.${name}` : `req.headers["${name}"]`
  ),
  'res.headers["set-cookie"]'
];

const MAX_IMPORTED_SBOM_BYTES = 5 * 1024 * 1024; // 5 MiB
const API_BODY_LIMIT_BYTES = 10 * 1024 * 1024; // 10 MiB

type PinoRedactConfig =
  | string[]
  | {
      paths?: unknown;
      remove?: boolean;
      censor?: unknown;
    };

function mergeRedactConfig(redact: unknown): PinoRedactConfig {
  if (Array.isArray(redact)) {
    const merged = new Set([...redact, ...FASTIFY_LOG_REDACT_PATHS]);
    return Array.from(merged);
  }

  if (redact && typeof redact === 'object') {
    const candidate = redact as { paths?: unknown; remove?: boolean; censor?: unknown };
    const existingPaths = Array.isArray(candidate.paths) ? candidate.paths : [];
    const mergedPaths = Array.from(new Set([...existingPaths, ...FASTIFY_LOG_REDACT_PATHS]));

    return {
      ...candidate,
      paths: mergedPaths,
      remove: candidate.remove ?? true
    } satisfies { paths: string[]; remove?: boolean; censor?: unknown };
  }

  return { paths: FASTIFY_LOG_REDACT_PATHS, remove: true } satisfies {
    paths: string[];
    remove: boolean;
  };
}

function resolveLoggerOption(
  input: FastifyServerOptions['logger'] | undefined,
  defaults: PinoLoggerOptions
): FastifyServerOptions['logger'] {
  if (input === undefined || input === true) {
    return defaults;
  }

  if (input === false) {
    return false;
  }

  if (input && typeof (input as { info?: unknown }).info === 'function') {
    return input;
  }

  const provided = (input ?? {}) as Record<string, unknown> & { redact?: unknown };
  const { redact, ...rest } = provided;

  return {
    ...defaults,
    ...rest,
    redact: mergeRedactConfig(redact)
  } satisfies PinoLoggerOptions;
}

const BooleanFlagSchema = z
  .string()
  .trim()
  .transform((value) => value.toLowerCase())
  .refine(
    (value) => value === 'true' || value === 'false' || value === '1' || value === '0',
    'Boolean environment flags must be true or false.'
  )
  .transform((value) => value === 'true' || value === '1');

const ApiConfigSchema = z.object({
  DATABASE_URL: z
    .string({ required_error: 'DATABASE_URL must be configured.' })
    .min(1, 'DATABASE_URL must be configured.'),
  REDIS_URL: z
    .string({ required_error: 'REDIS_URL must be configured.' })
    .min(1, 'REDIS_URL must be configured.'),
  API_KEYS_SALT: z
    .string({ required_error: 'API_KEYS_SALT must be configured.' })
    .min(1, 'API_KEYS_SALT must be configured.'),
  LICENSE_PUBLIC_KEY: z
    .string({ required_error: 'LICENSE_PUBLIC_KEY must be configured.' })
    .min(1, 'LICENSE_PUBLIC_KEY must be configured.'),
  WEBHOOK_SECRET_KEY: z
    .string({ required_error: 'WEBHOOK_SECRET_KEY must be configured.' })
    .min(1, 'WEBHOOK_SECRET_KEY must be configured.'),
  MAX_CONCURRENCY: z.coerce
    .number({ invalid_type_error: 'MAX_CONCURRENCY must be a positive integer.' })
    .int()
    .positive('MAX_CONCURRENCY must be a positive integer.'),
  SCAN_TIMEOUT_S: z.coerce
    .number({ invalid_type_error: 'SCAN_TIMEOUT_S must be a positive integer.' })
    .int()
    .positive('SCAN_TIMEOUT_S must be a positive integer.'),
  WEBHOOK_MAX_RETRY: z.coerce
    .number({ invalid_type_error: 'WEBHOOK_MAX_RETRY must be zero or a positive integer.' })
    .int()
    .nonnegative('WEBHOOK_MAX_RETRY must be zero or a positive integer.'),
  PROMETHEUS_PORT: z.coerce
    .number({ invalid_type_error: 'PROMETHEUS_PORT must be a positive integer.' })
    .int()
    .positive('PROMETHEUS_PORT must be a positive integer.'),
  SCAN_QUEUE_NAME: z
    .string({ required_error: 'SCAN_QUEUE_NAME must be configured.' })
    .min(1, 'SCAN_QUEUE_NAME must be configured.'),
  TELEMETRY_ENABLED: BooleanFlagSchema.optional()
});

const SECRETS_MANAGER_PREFIX = 'secretsmanager://';

interface SecretsManagerUri {
  readonly secretId: string;
  readonly property?: string;
}

interface CachedSecretEntry {
  readonly value: string;
  readonly expiresAt: number;
  readonly timeout: NodeJS.Timeout;
}

type SecretsCache = Map<string, CachedSecretEntry>;

const SECRET_CACHE_TTL_MS = 5 * 60 * 1000;

const resolvedSecretCache: SecretsCache = new Map();
let secretsClient: SecretsManagerClient | null = null;

const REQUIRED_SCAN_FEATURE = 'scan:execute';
const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';
const IDEMPOTENCY_KEY_MAX_LENGTH = 128;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_\-]+$/;

function getSecretsManagerClient(): SecretsManagerClient {
  if (!secretsClient) {
    secretsClient = new SecretsManagerClient({});
  }

  return secretsClient;
}

function parseSecretsManagerUri(value: string): SecretsManagerUri {
  const remainder = value.slice(SECRETS_MANAGER_PREFIX.length);

  if (remainder.length === 0) {
    throw new Error('Secrets Manager URI must include a secret identifier.');
  }

  const [rawId, rawProperty] = remainder.split('#');
  const secretId = decodeURIComponent(rawId);

  if (!secretId) {
    throw new Error('Secrets Manager URI must include a non-empty secret identifier.');
  }

  const property = rawProperty ? decodeURIComponent(rawProperty) : undefined;

  return { secretId, property } as const;
}

async function resolveSecretsManagerValue(value: string, field: string): Promise<string> {
  if (!value.startsWith(SECRETS_MANAGER_PREFIX)) {
    return value;
  }

  const cached = resolvedSecretCache.get(value);
  const now = Date.now();
  if (cached && cached.expiresAt > now) {
    return cached.value;
  }

  if (cached) {
    clearTimeout(cached.timeout);
    resolvedSecretCache.delete(value);
  }

  const { secretId, property } = parseSecretsManagerUri(value);

  try {
    const client = getSecretsManagerClient();
    const response = await client.send(new GetSecretValueCommand({ SecretId: secretId }));

    const secretString =
      typeof response.SecretString === 'string'
        ? response.SecretString
        : response.SecretBinary
          ? Buffer.from(response.SecretBinary).toString('utf8')
          : undefined;

    if (typeof secretString !== 'string' || secretString.length === 0) {
      throw new Error('Secret does not contain a string payload.');
    }

    let resolved = secretString;

    if (property) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(secretString);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Secret payload is not valid JSON: ${message}`);
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Secret payload must be a JSON object when selecting a property.');
      }

      const candidate = (parsed as Record<string, unknown>)[property];
      if (typeof candidate !== 'string' || candidate.length === 0) {
        throw new Error(`Secret payload is missing string property "${property}".`);
      }

      resolved = candidate;
    }

    const expiresAt = Date.now() + SECRET_CACHE_TTL_MS;
    const timeout = setTimeout(() => {
      const entry = resolvedSecretCache.get(value);

      if (!entry) {
        return;
      }

      if (entry.expiresAt <= Date.now()) {
        resolvedSecretCache.delete(value);
      }
    }, SECRET_CACHE_TTL_MS);

    if (typeof timeout.unref === 'function') {
      timeout.unref();
    }

    resolvedSecretCache.set(value, {
      value: resolved,
      expiresAt,
      timeout
    });
    return resolved;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to resolve ${field} from AWS Secrets Manager: ${message}`);
  }
}

export function decodeWebhookSecretKey(value: string, field = 'WEBHOOK_SECRET_KEY'): Buffer {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error(`${field} must be configured and non-empty.`);
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(trimmed, 'base64');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${field} must be a base64-encoded 32-byte key. (${message})`);
  }

  const normalized = decoded.toString('base64').replace(/=+$/u, '');
  const candidate = trimmed.replace(/=+$/u, '');

  if (normalized !== candidate || decoded.length !== 32) {
    throw new Error(`${field} must be a base64-encoded 32-byte key.`);
  }

  return decoded;
}

export async function loadApiConfig(env: EnvSource = process.env): Promise<ApiRuntimeConfig> {
  const parsed = ApiConfigSchema.parse(env);

  const [databaseUrl, redisUrl, apiKeySalt, licensePublicKey, webhookSecretKey] = await Promise.all([
    resolveSecretsManagerValue(parsed.DATABASE_URL, 'DATABASE_URL'),
    resolveSecretsManagerValue(parsed.REDIS_URL, 'REDIS_URL'),
    resolveSecretsManagerValue(parsed.API_KEYS_SALT, 'API_KEYS_SALT'),
    resolveSecretsManagerValue(parsed.LICENSE_PUBLIC_KEY, 'LICENSE_PUBLIC_KEY'),
    resolveSecretsManagerValue(parsed.WEBHOOK_SECRET_KEY, 'WEBHOOK_SECRET_KEY')
  ]);

  const normalizedLicenseKey = validateLicensePublicKey(licensePublicKey, 'LICENSE_PUBLIC_KEY');
  const decodedWebhookSecretKey = decodeWebhookSecretKey(webhookSecretKey);

  return {
    databaseUrl,
    redisUrl,
    apiKeySalt,
    licensePublicKey: normalizedLicenseKey,
    maxConcurrency: parsed.MAX_CONCURRENCY,
    scanTimeoutSeconds: parsed.SCAN_TIMEOUT_S,
    webhookMaxRetry: parsed.WEBHOOK_MAX_RETRY,
    prometheusPort: parsed.PROMETHEUS_PORT,
    scanQueueName: parsed.SCAN_QUEUE_NAME,
    telemetryEnabled: parsed.TELEMETRY_ENABLED ?? false,
    webhookSecretKey: decodedWebhookSecretKey
  } as const;
}

export const __testSecretCacheTtlMs = SECRET_CACHE_TTL_MS;

export function __testResetApiSecretCache(): void {
  for (const entry of resolvedSecretCache.values()) {
    clearTimeout(entry.timeout);
  }
  resolvedSecretCache.clear();
  secretsClient = null;
}

interface DatabaseError extends Error {
  code?: string;
  detail?: string;
}

type CanonicalAuditValue =
  | string
  | number
  | boolean
  | null
  | CanonicalAuditValue[]
  | { [key: string]: CanonicalAuditValue };

function canonicalizeAuditValue(value: unknown): CanonicalAuditValue | undefined {
  if (Array.isArray(value)) {
    const normalizedEntries: CanonicalAuditValue[] = [];

    for (const entry of value) {
      const normalized = canonicalizeAuditValue(entry);

      if (normalized !== undefined) {
        normalizedEntries.push(normalized);
      }
    }

    return normalizedEntries;
  }

  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const normalized: { [key: string]: CanonicalAuditValue } = {};

    for (const key of sortedKeys) {
      const normalizedValue = canonicalizeAuditValue(record[key]);

      if (normalizedValue !== undefined) {
        normalized[key] = normalizedValue;
      }
    }

    return normalized;
  }

  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    value === null
  ) {
    return value;
  }

  return undefined;
}

function normalizeAuditPayload(payload: unknown): CanonicalAuditValue {
  const normalized = canonicalizeAuditValue(payload);

  if (normalized === undefined) {
    return {} as { [key: string]: CanonicalAuditValue };
  }

  return normalized;
}

function normalizeRoles(value: unknown): Role[] {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    const roles = value
      .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
      .filter((entry): entry is string => entry.length > 0)
      .map((entry) => entry[0].toUpperCase() + entry.slice(1).toLowerCase());

    const validRoles = new Set<Role>(['Admin', 'Security', 'Legal', 'Developer', 'Auditor']);

    return roles.filter((role): role is Role => validRoles.has(role as Role));
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return normalizeRoles([value]);
  }

  if (value && typeof value === 'object') {
    if (Array.isArray((value as { roles?: unknown }).roles)) {
      return normalizeRoles((value as { roles: unknown }).roles);
    }
  }

  return [];
}

async function ensureRoleAccess(
  request: FastifyRequest,
  reply: FastifyReply,
  requiredRoles: Role[]
): Promise<AuthContext | undefined> {
  const authContext = request.authContext;

  if (!authContext) {
    await sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    return undefined;
  }

  if (requiredRoles.length === 0) {
    return authContext;
  }

  const hasRole = authContext.roles.some((role) => requiredRoles.includes(role));

  if (!hasRole) {
    await sendError(reply, request, 403, 'forbidden', 'Insufficient role privileges.');
    return undefined;
  }

  return authContext;
}

interface AuditEventInput {
  readonly tenantId: string;
  readonly projectId?: string | null;
  readonly scanId?: string | null;
  readonly actorType: string;
  readonly actorIdentifier?: string | null;
  readonly eventType: string;
  readonly payload: unknown;
}

async function recordAuditEvent(db: Database, event: AuditEventInput): Promise<void> {
  const normalizedPayload = normalizeAuditPayload(event.payload);
  const serialized = JSON.stringify(normalizedPayload);
  const eventHash = createHash('sha256').update(serialized).digest('hex');

  await db.query(
    `INSERT INTO audit_log_events (tenant_id, project_id, scan_id, actor_type, actor_identifier, event_type, event_payload, event_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      event.tenantId,
      event.projectId ?? null,
      event.scanId ?? null,
      event.actorType,
      event.actorIdentifier ?? null,
      event.eventType,
      normalizedPayload,
      eventHash
    ]
  );
}

function toIsoTimestamp(value: Date | string): string {
  if (value instanceof Date) {
    return value.toISOString();
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
}

function encodeAuditCursor(input: { createdAt: string; id: string }): string {
  const payload = JSON.stringify({ created_at: input.createdAt, id: input.id });
  return Buffer.from(payload, 'utf8').toString('base64url');
}

function decodeAuditCursor(cursor: string): { created_at: string; id: string } | null {
  try {
    const raw = Buffer.from(cursor, 'base64url').toString('utf8');
    const parsed = JSON.parse(raw) as { created_at?: unknown; id?: unknown } | null;

    if (!parsed || typeof parsed.created_at !== 'string' || typeof parsed.id !== 'string') {
      return null;
    }

    return { created_at: parsed.created_at, id: parsed.id };
  } catch {
    return null;
  }
}

function normalizeReportsSummaryRow(row?: ReportsSummaryAggregate | null): NormalizedReportsSummary {
  const toNumber = (value: string | number | null | undefined): number => {
    const numeric = typeof value === 'string' || typeof value === 'number' ? Number(value) : 0;
    return Number.isFinite(numeric) ? numeric : 0;
  };

  const totalScans = toNumber(row?.total_scans);
  const policyPass = toNumber(row?.policy_pass);
  const policyWarn = toNumber(row?.policy_warn);
  const policyFail = toNumber(row?.policy_fail);
  const licenseViolations = toNumber(row?.license_violations);
  const avgCandidate =
    typeof row?.average_duration_ms === 'string' || typeof row?.average_duration_ms === 'number'
      ? Number(row.average_duration_ms)
      : null;
  const averageDuration = Number.isFinite(avgCandidate ?? NaN) ? avgCandidate : null;
  const vulnerabilities = {
    critical: toNumber(row?.vuln_critical),
    high: toNumber(row?.vuln_high),
    medium: toNumber(row?.vuln_medium),
    low: toNumber(row?.vuln_low)
  } satisfies NormalizedReportsSummary['vulnerabilities'];
  const vexTotal = toNumber(row?.vex_total);
  const vexDowngraded = toNumber(row?.vex_downgraded);
  const ratio = vexTotal > 0 ? vexDowngraded / vexTotal : 0;

  return {
    total_scans: totalScans,
    policy: { pass: policyPass, warn: policyWarn, fail: policyFail },
    license_violations: licenseViolations,
    average_duration_ms: averageDuration,
    vulnerabilities,
    vex_noise_reduction: {
      total: vexTotal,
      downgraded: vexDowngraded,
      ratio
    }
  } satisfies NormalizedReportsSummary;
}

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }

  const stringValue = String(value);
  if (/[",\n]/u.test(stringValue)) {
    return `"${stringValue.replace(/"/g, '""')}"`;
  }

  return stringValue;
}

interface ProjectRow {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  repo_url: string | null;
  oci_ref: string | null;
  metadata: Record<string, unknown>;
  created_at: Date | string;
  updated_at: Date | string;
}

interface ArtifactRow {
  id: string;
  project_id: string;
  type: string;
  ref: Record<string, unknown>;
  metadata: Record<string, unknown>;
  created_at: Date | string;
}

interface ScanRow {
  id: string;
  project_id: string;
  artifact_id: string | null;
  policy_id: string | null;
  policy_result: string | null;
  status: string;
  findings: Record<string, unknown>;
  duration_ms: number | string | null;
  started_at: Date | string;
  completed_at: Date | string | null;
  created_at: Date | string;
}

interface SbomRow {
  format: string;
  bom: Record<string, unknown>;
}

interface LicenseRow {
  id: string;
  sbom_id: string;
  scan_id: string | null;
  component_purl: string;
  detected_spdx_id: string | null;
  evidence: Record<string, unknown>;
  created_at: Date | string;
}

interface LegalFindingRow {
  id: string;
  tenant_id: string;
  license_id: string | null;
  vuln_id: string | null;
  scan_id: string | null;
  status: string;
  obligations: Record<string, unknown>;
  notes: string | null;
  created_at: Date | string;
}

interface LegalDecisionRow {
  id: string;
  tenant_id: string;
  finding_id: string;
  decision: string;
  rationale: string | null;
  decided_by: string | null;
  decided_at: Date | string;
  expires_at: Date | string | null;
  metadata: Record<string, unknown>;
}

interface LegalSignoffRow {
  id: string;
  tenant_id: string;
  decision_id: string;
  signer_name: string;
  signer_email: string | null;
  signature_hash: string;
  signature_payload: Record<string, unknown>;
  signed_at: Date | string;
}

interface VulnRow {
  id: string;
  scan_id: string;
  component_purl: string;
  source: string;
  cve_id: string | null;
  severity: string | null;
  cvss: number | string | null;
  summary: string | null;
  fixed_version: string | null;
  detected_at: Date | string;
}

interface PolicyRow {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  rules: unknown;
  created_at: Date | string;
  updated_at: Date | string;
}

interface PolicyRules {
  allowed_spdx: string[];
  denied_spdx: string[];
  cvss_threshold: number | null;
  allowlists: {
    licenses: string[];
    vulnerabilities: string[];
  };
}

type PolicyResponse = Omit<PolicyRow, 'rules'> & { rules: PolicyRules };

interface WebhookRow {
  id: string;
  tenant_id: string;
  url: string;
  secret_ciphertext: Buffer | null;
  secret_iv: Buffer | null;
  secret_auth_tag: Buffer | null;
  secret_last_four: string | null;
  events: string[];
  created_at: Date | string;
  updated_at: Date | string;
}

interface WebhookDeliveryMetadata {
  last_success_at: Date | string | null;
  last_failure_at: Date | string | null;
  failure_count: number | null;
}

interface AuditEventRow {
  id: string;
  tenant_id: string;
  project_id: string | null;
  scan_id: string | null;
  actor_type: string;
  actor_identifier: string | null;
  event_type: string;
  event_payload: Record<string, unknown> | null;
  event_hash: string;
  created_at: Date | string;
}

interface ReportsSummaryAggregate {
  total_scans: string | number | null;
  policy_pass: string | number | null;
  policy_warn: string | number | null;
  policy_fail: string | number | null;
  license_violations: string | number | null;
  average_duration_ms: string | number | null;
  vuln_critical: string | number | null;
  vuln_high: string | number | null;
  vuln_medium: string | number | null;
  vuln_low: string | number | null;
  vex_total: string | number | null;
  vex_downgraded: string | number | null;
}

interface NormalizedReportsSummary {
  total_scans: number;
  policy: Record<'pass' | 'warn' | 'fail', number>;
  license_violations: number;
  average_duration_ms: number | null;
  vulnerabilities: Record<'critical' | 'high' | 'medium' | 'low', number>;
  vex_noise_reduction: {
    total: number;
    downgraded: number;
    ratio: number;
  };
}

interface UsageMetricRow {
  period_start: Date | string;
  period_end: Date | string;
  metrics: unknown;
}

type NormalizedPolicyResult = 'pass' | 'warn' | 'fail' | null;

const ARGON2_OPTIONS: argon2.Options & { type: argon2.Type } = {
  type: argon2.argon2id,
  memoryCost: 15_360,
  timeCost: 2,
  parallelism: 1
};

function computeApiKeyLookupHash(token: string, salt: string): string {
  return createHash('sha256').update(`${salt}:${token}`).digest('hex');
}

async function hashApiKeyDigest(lookupHash: string): Promise<string> {
  return argon2.hash(lookupHash, ARGON2_OPTIONS);
}

function isArgon2Digest(value: string): boolean {
  return typeof value === 'string' && value.startsWith('$argon2');
}

async function verifyApiKeyDigest(
  record: ApiKeyRecord,
  lookupHash: string,
  options: { db: Database; logger?: { warn: (meta: unknown, message?: string) => void } }
): Promise<boolean> {
  const digest = record.token_hash;

  if (!digest || typeof digest !== 'string') {
    return false;
  }

  if (isArgon2Digest(digest)) {
    try {
      return await argon2.verify(digest, lookupHash);
    } catch (error) {
      options.logger?.warn?.({ err: error, api_key_id: record.id }, 'argon2 verification failed');
      return false;
    }
  }

  try {
    const legacyBuffer = Buffer.from(digest, 'hex');
    const lookupBuffer = Buffer.from(lookupHash, 'hex');

    if (legacyBuffer.length !== lookupBuffer.length) {
      return false;
    }

    const matches = timingSafeEqual(legacyBuffer, lookupBuffer);

    if (matches) {
      try {
        const upgradedDigest = await hashApiKeyDigest(lookupHash);
        await options.db.query('UPDATE api_keys SET token_hash = $1 WHERE id = $2', [upgradedDigest, record.id]);
        record.token_hash = upgradedDigest;
      } catch (error) {
        options.logger?.warn?.({ err: error, api_key_id: record.id }, 'argon2 upgrade failed');
      }
    }

    return matches;
  } catch {
    return false;
  }
}

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

function wrapLookupWithCache<T>(
  fetcher: (tokenHash: string) => Promise<T>,
  options: { ttlMs?: number; maxEntries?: number; now?: () => number } = {}
): (tokenHash: string) => Promise<T> {
  const ttlMs = Math.max(options.ttlMs ?? 5_000, 1);
  const maxEntries = Math.max(options.maxEntries ?? 1_024, 1);
  const nowFn = options.now ?? (() => Date.now());
  const cache = new Map<string, CacheEntry<T>>();

  return async (tokenHash: string) => {
    const now = nowFn();
    const cached = cache.get(tokenHash);

    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const value = await fetcher(tokenHash);
    cache.set(tokenHash, { value, expiresAt: now + ttlMs });

    for (const [key, entry] of cache) {
      if (entry.expiresAt <= now) {
        cache.delete(key);
      }
    }

    if (cache.size > maxEntries) {
      let oldestKey: string | undefined;
      let oldestExpiry = Number.POSITIVE_INFINITY;

      for (const [key, entry] of cache) {
        if (entry.expiresAt < oldestExpiry) {
          oldestExpiry = entry.expiresAt;
          oldestKey = key;
        }
      }

      if (oldestKey) {
        cache.delete(oldestKey);
      }
    }

    return value;
  };
}

function hashIdempotencyKey(key: string, salt: string): string {
  return createHash('sha256').update(`${salt}:scan:${key}`).digest('hex');
}

function extractIdempotencyKey(value: unknown): string | null {
  if (typeof value === 'string') {
    return value;
  }

  if (Array.isArray(value) && typeof value[0] === 'string') {
    return value[0];
  }

  return null;
}

async function fetchExistingScanForKey(
  db: Database,
  tenantId: string,
  keyHash: string
): Promise<ScanRow | null> {
  const maxAttempts = 5;
  let delayMs = 10;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const requestResult = await db.query<{ scan_id: string | null }>(
      `SELECT scan_id FROM scan_requests WHERE tenant_id = $1 AND key_hash = $2 LIMIT 1`,
      [tenantId, keyHash]
    );

    const scanId = requestResult.rows[0]?.scan_id ?? null;

    if (scanId) {
      const scanResult = await db.query<ScanRow>(
        `SELECT s.id, s.project_id, s.artifact_id, s.policy_id, s.policy_result, s.status, s.findings, s.duration_ms, s.started_at, s.completed_at, s.created_at
           FROM scans s
           INNER JOIN projects p ON p.id = s.project_id
           WHERE s.id = $1 AND p.tenant_id = $2
           LIMIT 1`,
        [scanId, tenantId]
      );

      const scan = scanResult.rows[0];

      if (scan) {
        return scan;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, delayMs));
    delayMs = Math.min(delayMs * 2, 160);
  }

  return null;
}

function shouldAuthenticate(request: FastifyRequest): boolean {
  const url = request.raw.url ?? '';

  if (url.startsWith('/v1/health') || url.startsWith('/health/panel')) {
    return false;
  }

  if (url.startsWith('/v1/auth/sso/')) {
    return false;
  }

  return url.startsWith('/v1');
}

function extractBearerToken(headerValue: unknown): string | null {
  if (typeof headerValue !== 'string') {
    return null;
  }

  const match = headerValue.match(/^Bearer\s+(.+)$/iu);
  if (!match) {
    return null;
  }

  const token = match[1]?.trim();
  return token && token.length > 0 ? token : null;
}

function normalizePolicyResult(value: string | null): NormalizedPolicyResult {
  if (!value) {
    return null;
  }

  const normalized = value.toLowerCase();

  if (normalized === 'allowed' || normalized === 'pass') {
    return 'pass';
  }

  if (normalized === 'warn' || normalized === 'warning' || normalized === 'pending') {
    return 'warn';
  }

  if (normalized === 'fail' || normalized === 'failed' || normalized === 'denied') {
    return 'fail';
  }

  return 'pass';
}

interface ScanLinks {
  self: string;
  sbom: string;
  vulns: string;
  licenses: string;
}

type SerializedScan = Omit<ScanRow, 'policy_result' | 'duration_ms'> & {
  policy_result: NormalizedPolicyResult;
  duration_ms: number | null;
  links: ScanLinks;
};

function serializeScan(row: ScanRow): SerializedScan {
  const links: ScanLinks = {
    self: `/v1/scans/${row.id}`,
    sbom: `/v1/sboms/${row.id}`,
    vulns: `/v1/vulns?scan_id=${row.id}`,
    licenses: `/v1/licenses?scan_id=${row.id}`
  };

  return {
    ...row,
    policy_result: normalizePolicyResult(row.policy_result),
    duration_ms: typeof row.duration_ms === 'string' ? Number(row.duration_ms) : row.duration_ms ?? null,
    links
  };
}

function extractLicenseViolationCount(findings: Record<string, unknown>): number {
  if (!findings) {
    return 0;
  }

  const direct = findings['license_violations'] ?? findings['licenseViolations'];

  if (typeof direct === 'number' && Number.isFinite(direct)) {
    return direct;
  }

  if (Array.isArray(direct)) {
    return direct.length;
  }

  const licensesContainer = findings['licenses'];
  const nested =
    licensesContainer && typeof licensesContainer === 'object'
      ? (licensesContainer as Record<string, unknown>)['violations']
      : undefined;

  if (typeof nested === 'number' && Number.isFinite(nested)) {
    return nested;
  }

  if (Array.isArray(nested)) {
    return nested.length;
  }

  return 0;
}

type SerializedVulnerability = Omit<VulnRow, 'cvss'> & { cvss: number | null };

type SerializedLicense = Omit<LicenseRow, 'scan_id' | 'detected_spdx_id'> & {
  scan_id: string | null;
  detected_spdx_id: string | null;
};

const artifactDetailsSchema = z.object({
  type: z.enum(['git', 'archive', 'oci']),
  ref: z.record(z.unknown()),
  metadata: z.record(z.unknown()).optional()
});

type ArtifactDetails = z.infer<typeof artifactDetailsSchema>;

function extractDefaultBranch(metadata: Record<string, unknown>): string | undefined {
  const candidate = metadata.default_branch;
  return typeof candidate === 'string' && candidate.length > 0 ? candidate : undefined;
}

function buildAutoArtifact(project: ProjectRow): ArtifactDetails | null {
  if (project.repo_url) {
    const metadata =
      typeof project.metadata === 'object' && project.metadata !== null
        ? project.metadata
        : {};
    const branch = extractDefaultBranch(metadata) ?? 'main';
    return {
      type: 'git',
      ref: { url: project.repo_url, branch },
      metadata: { source: 'project' }
    } satisfies ArtifactDetails;
  }

  if (project.oci_ref) {
    const ref = project.oci_ref;
    const firstSlash = ref.indexOf('/');

    if (firstSlash === -1) {
      return null;
    }

    const registry = ref.slice(0, firstSlash);
    const remainder = ref.slice(firstSlash + 1);
    const digestIndex = remainder.indexOf('@');
    const tagIndex = remainder.indexOf(':');

    let repository = remainder;
    let tag: string | undefined;
    let digest: string | undefined;

    if (digestIndex !== -1) {
      repository = remainder.slice(0, digestIndex);
      digest = remainder.slice(digestIndex + 1);
    }

    if (tagIndex !== -1 && (digestIndex === -1 || tagIndex < digestIndex)) {
      repository = remainder.slice(0, tagIndex);
      tag = remainder.slice(tagIndex + 1, digestIndex === -1 ? undefined : digestIndex);
    }

    return {
      type: 'oci',
      ref: {
        registry,
        repository,
        tag: tag ?? undefined,
        digest: digest ?? undefined
      },
      metadata: { source: 'project' }
    } satisfies ArtifactDetails;
  }

  return null;
}

function normalizeCvssValue(value: number | string | null): number | null {
  if (value === null) {
    return null;
  }

  if (typeof value === 'number') {
    return Number.isNaN(value) ? null : value;
  }

  const parsed = Number(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function serializeVulnerability(row: VulnRow): SerializedVulnerability {
  return {
    ...row,
    cvss: normalizeCvssValue(row.cvss)
  };
}

function serializeLicense(row: LicenseRow): SerializedLicense {
  return {
    ...row,
    scan_id: row.scan_id ?? null,
    detected_spdx_id: row.detected_spdx_id ?? null
  };
}

type RateLimitScope = 'minute' | 'day';

interface RateLimitWindowConfig {
  readonly scope: RateLimitScope;
  readonly limit: number;
  readonly windowSeconds: number;
}

interface RateLimitEntry {
  readonly scope: RateLimitScope;
  readonly limit: number;
  readonly remaining: number;
  readonly resetSeconds: number;
  readonly blocked: boolean;
}

interface RateLimitCheckResult {
  readonly entries: RateLimitEntry[];
  readonly blocked: RateLimitEntry | null;
}

export const RATE_LIMITER_DEBUG_STORE_SIZE = Symbol('atlas.rateLimiter.debugStoreSize');

export type RateLimiter = ((apiKeyId: string, now: Date) => Promise<RateLimitCheckResult>) & {
  [RATE_LIMITER_DEBUG_STORE_SIZE]?: () => number;
};

function sendError(
  reply: FastifyReply,
  request: FastifyRequest,
  statusCode: number,
  code: string,
  message: string,
  meta?: Record<string, unknown>
): FastifyReply {
  const sanitizedMessage = statusCode >= 500 ? 'An internal error occurred. Please contact support.' : message;
  return reply.status(statusCode).send({
    error: {
      code,
      message: sanitizedMessage,
      request_id: request.id,
      ...(meta ? { meta } : {})
    }
  });
}

function isRedisRateLimitConnection(
  redis: RedisConnection
): redis is RedisConnection & {
  incrby(key: string, value: number): Promise<number>;
  ttl(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
} {
  return (
    typeof (redis as { incrby?: unknown }).incrby === 'function' &&
    typeof (redis as { ttl?: unknown }).ttl === 'function' &&
    typeof (redis as { expire?: unknown }).expire === 'function'
  );
}

const RATE_LIMIT_WINDOWS: RateLimitWindowConfig[] = [
  { scope: 'minute', limit: 30, windowSeconds: 60 },
  { scope: 'day', limit: 10_000, windowSeconds: 86_400 }
];

const RATE_LIMIT_CLEANUP_INTERVAL_MS = 1_000;

const DEFAULT_USAGE_METRIC_KEYS = ['req_count', 'scans_started', 'scans_succeeded'] as const;
const UNSAFE_USAGE_METRIC_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function isSafeUsageMetricKey(key: string): boolean {
  return !UNSAFE_USAGE_METRIC_KEYS.has(key);
}

type NormalizedUsageMetrics = Record<string, number> & {
  readonly req_count: number;
  readonly scans_started: number;
  readonly scans_succeeded: number;
};

function toIsoString(value: Date | string): string {
  if (value instanceof Date) {
    return value.toISOString();
  }

  const timestamp = Date.parse(value);
  if (!Number.isNaN(timestamp)) {
    return new Date(timestamp).toISOString();
  }

  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function startOfUtcDay(date: Date): Date {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function addUtcDays(date: Date, amount: number): Date {
  const result = new Date(date);
  result.setUTCDate(result.getUTCDate() + amount);
  return result;
}

function normalizeUsageMetrics(
  metrics: Record<string, unknown>,
  requiredKeys: Iterable<string> = DEFAULT_USAGE_METRIC_KEYS
): NormalizedUsageMetrics {
  const result: Record<string, number> = {};

  for (const key of requiredKeys) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    result[key] = 0;
  }

  for (const key of DEFAULT_USAGE_METRIC_KEYS) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    result[key] = result[key] ?? 0;
  }

  for (const [key, rawValue] of Object.entries(metrics)) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    const numericValue =
      typeof rawValue === 'number'
        ? rawValue
        : typeof rawValue === 'string'
          ? Number(rawValue)
          : Number.NaN;

    if (Number.isFinite(numericValue)) {
      result[key] = numericValue;
    }
  }

  return result as NormalizedUsageMetrics;
}

function ensureUsageMetricKeys(
  metrics: NormalizedUsageMetrics,
  keys: Iterable<string>
): NormalizedUsageMetrics {
  const result: Record<string, number> = {};

  for (const [key, value] of Object.entries(metrics)) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    result[key] = value;
  }

  for (const key of keys) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    if (!(key in result)) {
      result[key] = 0;
    }
  }

  for (const key of DEFAULT_USAGE_METRIC_KEYS) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    if (!(key in result)) {
      result[key] = 0;
    }
  }

  return result as NormalizedUsageMetrics;
}

function createEmptyUsageMetrics(keys: Iterable<string>): NormalizedUsageMetrics {
  const keySet = new Set(
    Array.from(keys).filter((key): key is string => typeof key === 'string' && isSafeUsageMetricKey(key))
  );

  for (const key of DEFAULT_USAGE_METRIC_KEYS) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    keySet.add(key);
  }

  return normalizeUsageMetrics({}, keySet);
}

function accumulateUsageTotals(rows: NormalizedUsageMetrics[]): NormalizedUsageMetrics {
  const totals: Record<string, number> = {};

  for (const key of DEFAULT_USAGE_METRIC_KEYS) {
    if (!isSafeUsageMetricKey(key)) {
      continue;
    }
    totals[key] = 0;
  }

  for (const row of rows) {
    for (const [key, value] of Object.entries(row)) {
      if (!isSafeUsageMetricKey(key)) {
        continue;
      }
      totals[key] = (totals[key] ?? 0) + value;
    }
  }

  return totals as NormalizedUsageMetrics;
}

export function createRateLimiter(redis: RedisConnection): RateLimiter {
  const keyPrefix = 'rate_limit';

  if (isRedisRateLimitConnection(redis)) {
    return async (apiKeyId: string, now: Date) => {
      void now;
      const entries: RateLimitEntry[] = [];

      for (const windowConfig of RATE_LIMIT_WINDOWS) {
        const redisKey = `${keyPrefix}:${windowConfig.scope}:${apiKeyId}`;
        const count = await redis.incrby(redisKey, 1);
        let ttl = await redis.ttl(redisKey);

        if (ttl < 0) {
          await redis.expire(redisKey, windowConfig.windowSeconds);
          ttl = windowConfig.windowSeconds;
        }

        const remainingRaw = windowConfig.limit - count;
        const remaining = remainingRaw > 0 ? remainingRaw : 0;
        const blocked = count > windowConfig.limit;
        const resetSeconds = ttl >= 0 ? ttl : windowConfig.windowSeconds;

        entries.push({
          scope: windowConfig.scope,
          limit: windowConfig.limit,
          remaining,
          resetSeconds,
          blocked
        });
      }

      return {
        entries,
        blocked: entries.find((entry) => entry.blocked) ?? null
      } satisfies RateLimitCheckResult;
    };
  }

  const inMemoryStore = new Map<string, { count: number; expiresAt: number }>();
  let nextCleanupTime = 0;

  const limiter: RateLimiter = (apiKeyId: string, now: Date) => {
    const entries: RateLimitEntry[] = [];
    const timestamp = now.getTime();

    if (timestamp >= nextCleanupTime) {
      if (inMemoryStore.size > 0) {
        for (const [storeKey, entry] of inMemoryStore) {
          if (!entry || !Number.isFinite(entry.expiresAt) || entry.expiresAt <= timestamp) {
            inMemoryStore.delete(storeKey);
          }
        }
      }
      nextCleanupTime = timestamp + RATE_LIMIT_CLEANUP_INTERVAL_MS;
    }

    for (const windowConfig of RATE_LIMIT_WINDOWS) {
      const storeKey = `${keyPrefix}:${windowConfig.scope}:${apiKeyId}`;
      const existing = inMemoryStore.get(storeKey);
      const windowMs = windowConfig.windowSeconds * 1000;
      let count = 0;
      let expiresAt = timestamp + windowMs;

      if (existing && existing.expiresAt > timestamp) {
        count = existing.count;
        expiresAt = existing.expiresAt;
      }

      count += 1;
      if (count === 1) {
        expiresAt = timestamp + windowMs;
      }

      inMemoryStore.set(storeKey, { count, expiresAt });

      const remainingRaw = windowConfig.limit - count;
      const remaining = remainingRaw > 0 ? remainingRaw : 0;
      const blocked = count > windowConfig.limit;
      const resetSeconds = Math.max(Math.ceil((expiresAt - timestamp) / 1000), 0);

      entries.push({
        scope: windowConfig.scope,
        limit: windowConfig.limit,
        remaining,
        resetSeconds,
        blocked
      });
    }

    return Promise.resolve({
      entries,
      blocked: entries.find((entry) => entry.blocked) ?? null
    } satisfies RateLimitCheckResult);
  };

  if (!limiter[RATE_LIMITER_DEBUG_STORE_SIZE]) {
    Object.defineProperty(limiter, RATE_LIMITER_DEBUG_STORE_SIZE, {
      value: () => inMemoryStore.size,
      enumerable: false
    });
  }

  return limiter;
}

export async function buildServer(options: BuildServerOptions): Promise<FastifyInstance> {
  const resolvedApiKeySalt = (options.apiKeySalt ?? process.env.API_KEYS_SALT ?? '').trim();

  if (!resolvedApiKeySalt) {
    throw new Error('API_KEYS_SALT must be configured and non-empty.');
  }

  const webhookSecretKey = options.webhookSecretKey
    ? Buffer.from(options.webhookSecretKey)
    : process.env.WEBHOOK_SECRET_KEY
    ? decodeWebhookSecretKey(process.env.WEBHOOK_SECRET_KEY)
    : null;

  if (!webhookSecretKey || webhookSecretKey.length !== 32) {
    throw new Error('WEBHOOK_SECRET_KEY must be configured and decode to 32 bytes.');
  }

  const rawLicensePublicKey = (options.licensePublicKey ?? process.env.LICENSE_PUBLIC_KEY ?? '').trim();
  const resolvedLicensePublicKey = rawLicensePublicKey
    ? validateLicensePublicKey(rawLicensePublicKey, 'LICENSE_PUBLIC_KEY')
    : rawLicensePublicKey;
  const rawFeedPublicKey = (options.feedPublicKey ?? process.env.FEED_PUBLIC_KEY ?? '').trim();
  const feedPublicKey = rawFeedPublicKey.length > 0 ? rawFeedPublicKey : null;

  const defaultLoggerOptions: PinoLoggerOptions = {
    level: 'info',
    redact: { paths: FASTIFY_LOG_REDACT_PATHS, remove: true }
  };

  const resolvedLoggerOption = resolveLoggerOption(options.logger, defaultLoggerOptions);
  const loggerForFastify =
    options.logDestination &&
    resolvedLoggerOption !== false &&
    typeof (resolvedLoggerOption as { info?: unknown }).info !== 'function'
      ? pino(resolvedLoggerOption as PinoLoggerOptions, options.logDestination)
      : resolvedLoggerOption;

  const app = Fastify({
    logger: loggerForFastify,
    bodyLimit: API_BODY_LIMIT_BYTES
  });

  const appendUpdateLog = async (
    entry: Parameters<typeof recordUpdateLogEntry>[0]
  ): Promise<void> => {
    try {
      await recordUpdateLogEntry(entry);
    } catch (error) {
      app.log.warn({ err: error, action: entry.action }, 'Failed to append update log entry');
    }
  };

  const resolveActiveFeedState = async (
    tenantId: string
  ): Promise<{ activeVersion: string | null; minimumDowngradeVersion: string | null }> => {
    const tenantMetadataResult = await db.query<{ metadata: Record<string, unknown> }>(
      'SELECT metadata FROM tenants WHERE id = $1 LIMIT 1',
      [tenantId]
    );

    const tenantMetadata = tenantMetadataResult.rows[0]?.metadata ?? {};
    const activeVersion =
      typeof tenantMetadata.active_feed_version === 'string'
        ? tenantMetadata.active_feed_version
        : null;

    if (!activeVersion) {
      return { activeVersion: null, minimumDowngradeVersion: null };
    }

    const metadataDowngrade =
      typeof tenantMetadata.minimum_downgrade_version === 'string'
        ? tenantMetadata.minimum_downgrade_version
        : null;

    if (metadataDowngrade) {
      return { activeVersion, minimumDowngradeVersion: metadataDowngrade };
    }

    const manifestResult = await db.query<{ manifest: Record<string, unknown> }>(
      `SELECT manifest
         FROM feed_manifests
        WHERE tenant_id = $1 AND version = $2
        ORDER BY imported_at DESC, id DESC
        LIMIT 1`,
      [tenantId, activeVersion]
    );

    const manifestRow = manifestResult.rows[0] ?? null;

    if (!manifestRow) {
      return { activeVersion, minimumDowngradeVersion: null };
    }

    try {
      const normalized = parseFeedManifest(manifestRow.manifest);
      return {
        activeVersion,
        minimumDowngradeVersion: normalized.minimumDowngradeVersion
      };
    } catch (error) {
      app.log.warn({ err: error }, 'Failed to parse active feed manifest while resolving downgrade floor');
      return { activeVersion, minimumDowngradeVersion: null };
    }
  };

  const tracer =
    options.tracer ?? createTracer('atlas-sca-api', { enabled: options.telemetryEnabled === true });
  const requestSpanKey: unique symbol = Symbol('requestSpan');

  app.addHook('onRequest', async (request, reply) => {
    const parentContext = tracer.extract(request.headers as Record<string, string | string[] | undefined>);
    const span = tracer.startSpan('http.request', {
      parentContext,
      attributes: {
        'http.method': request.method,
        'http.route': request.routerPath ?? request.url,
        'http.request_id': request.id
      }
    });
    const carrier: Record<string, string> = {};
    tracer.inject(carrier, span.context);
    if (carrier.traceparent) {
      reply.header('traceparent', carrier.traceparent);
    }
    reply.header('x-request-id', request.id);
    (request as Record<symbol, unknown>)[requestSpanKey] = span;
  });

  app.addHook('onResponse', async (request, reply) => {
    const span = (request as Record<symbol, unknown>)[requestSpanKey] as SpanHandle | undefined;
    if (span) {
      span.setAttribute('http.status_code', reply.statusCode);
      if (reply.statusCode >= 500) {
        span.setStatus('error', `HTTP ${reply.statusCode}`);
      } else {
        span.setStatus('ok');
      }
      span.end();
    }
  });

  app.get('/v1/api-keys', async (request, reply) => {
    const parsed = listApiKeysQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;

    const keysResult = await db.query<ApiKeyRecord & {
      name: string;
      token_lookup_hash: string | null;
      created_at: Date | string;
      last_used_at: Date | string | null;
    }>(
      `SELECT id, name, permissions, created_at, last_used_at, token_lookup_hash
         FROM api_keys
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3`,
      [authContext.tenantId, pageSize, offset]
    );

    const countResult = await db.query<{ count: string | number }>(
      'SELECT COUNT(*)::bigint AS count FROM api_keys WHERE tenant_id = $1',
      [authContext.tenantId]
    );

    const totalCount = Number.parseInt(String(countResult.rows[0]?.count ?? '0'), 10);

    const data = keysResult.rows.map((row) => {
      const roles = normalizeRoles(row.permissions);
      const lookupHash = row.token_lookup_hash ?? '';
      const lastFour = lookupHash.slice(-4) || '????';
      return {
        id: row.id,
        name: row.name,
        roles: roles.length > 0 ? roles : ['Developer'],
        created_at: row.created_at,
        last_used_at: row.last_used_at ?? null,
        masked_token: `•••• ${lastFour}`,
        last_four: lastFour
      };
    });

    return reply.status(200).send({
      data,
      pagination: { page, page_size: pageSize, count: totalCount }
    });
  });

  app.post('/v1/api-keys', async (request, reply) => {
    const parsed = createApiKeySchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const normalizedName = payload.name.trim();

    if (normalizedName.length === 0) {
      return sendError(reply, request, 400, 'validation_error', 'API key name cannot be empty.');
    }

    const uniqueRoles = Array.from(new Set(payload.roles));
    const token = `aka_${randomUUID().replace(/-/g, '')}`;
    const lookupHash = computeApiKeyLookupHash(token, apiKeySalt);

    let digest: string;

    try {
      digest = await hashApiKeyDigest(lookupHash);
    } catch (error) {
      request.log.error({ err: error }, 'Failed to hash API key secret.');
      return sendError(reply, request, 500, 'internal_error', 'Failed to generate API key.');
    }

    let apiKeyId: string | undefined;
    let createdAt: Date | string = new Date().toISOString();

    try {
      const result = await db.query<{ id: string; created_at: Date | string }>(
        `INSERT INTO api_keys (tenant_id, name, token_hash, token_lookup_hash, permissions)
           VALUES ($1, $2, $3, $4, $5::jsonb)
        ON CONFLICT (tenant_id, name) DO NOTHING
        RETURNING id, created_at`,
        [authContext.tenantId, normalizedName, digest, lookupHash, JSON.stringify(uniqueRoles)]
      );

      apiKeyId = result.rows[0]?.id;
      createdAt = result.rows[0]?.created_at ?? createdAt;

      if (!apiKeyId) {
        return sendError(reply, request, 409, 'conflict', 'An API key with this name already exists.');
      }
    } catch (error) {
      if ((error as { code?: string }).code === '23505') {
        return sendError(reply, request, 409, 'conflict', 'An API key with this name already exists.');
      }

      request.log.error({ err: error }, 'Failed to create API key.');
      return sendError(reply, request, 500, 'internal_error', 'Failed to create API key.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'api_key.created',
      payload: { api_key_id: apiKeyId, name: normalizedName, roles: uniqueRoles }
    });

    return reply.status(201).send({
      data: {
        id: apiKeyId,
        name: normalizedName,
        roles: uniqueRoles,
        created_at: createdAt,
        last_used_at: null,
        last_four: token.slice(-4),
        masked_token: `•••• ${token.slice(-4)}`,
        plaintext_token: token
      }
    });
  });

  app.delete('/v1/api-keys/:id', async (request, reply) => {
    const paramsResult = deleteApiKeyParamsSchema.safeParse(request.params);

    if (!paramsResult.success) {
      return sendError(reply, request, 400, 'validation_error', 'Invalid API key identifier.');
    }

    const bodyResult = deleteApiKeySchema.safeParse(request.body);

    if (!bodyResult.success) {
      const message = bodyResult.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    if (bodyResult.data.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    let deleted: ApiKeyRecord & { name: string } | undefined;

    try {
      const result = await db.query<(ApiKeyRecord & { name: string })>(
        `DELETE FROM api_keys
          WHERE id = $1 AND tenant_id = $2
        RETURNING id, tenant_id, name, permissions, token_hash`,
        [paramsResult.data.id, authContext.tenantId]
      );

      deleted = result.rows[0];
    } catch (error) {
      request.log.error({ err: error }, 'Failed to delete API key.');
      return sendError(reply, request, 500, 'internal_error', 'Failed to delete API key.');
    }

    if (!deleted) {
      return sendError(reply, request, 404, 'not_found', 'API key not found.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'api_key.deleted',
      payload: { api_key_id: deleted.id, name: deleted.name }
    });

    return reply.status(204).send();
  });

  app.post('/v1/feeds/upload', async (request, reply) => {
    const parsed = uploadFeedSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    const actor = `api_key:${authContext.apiKeyId ?? 'unknown'}`;

    if (payload.tenant_id !== authContext.tenantId) {
      await appendUpdateLog({
        action: 'feed.upload',
        manifest_id: null,
        version: payload.version,
        actor,
        result: 'failure',
        metadata: { reason: 'tenant_mismatch' }
      });
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    let normalized;

    try {
      normalized = parseFeedManifest(payload.manifest);
    } catch (error) {
      if (error instanceof FeedArchiveTooLargeError) {
        return sendError(reply, request, 413, 'payload_too_large', error.message);
      }

      const message = error instanceof Error ? error.message : 'Feed manifest is invalid.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    if (normalized.feedVersion !== payload.version) {
      return sendError(
        reply,
        request,
        400,
        'validation_error',
        'Feed manifest version does not match the provided version.'
      );
    }

    const trimmedSignature = typeof payload.signature === 'string' ? payload.signature.trim() : '';
    const signature = trimmedSignature.length > 0 ? trimmedSignature : null;

    try {
      await verifyFeedSignature({ manifest: payload.manifest, signature, publicKey: feedPublicKey ?? undefined });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Feed signature verification failed.';
      await appendUpdateLog({
        action: 'feed.upload',
        manifest_id: null,
        version: payload.version,
        actor,
        result: 'failure',
        metadata: {
          reason: 'signature_verification_failed',
          error: message
        }
      });
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const verifiedAt = signature ? new Date() : null;
    const now = new Date();
    let manifestId: string | null = null;

    try {
      manifestId = await runInTransaction(db, async (client) => {
        const manifestResult = await client.query<{ id: string }>(
          `INSERT INTO feed_manifests (tenant_id, version, manifest, signature, verified_at)
             VALUES ($1, $2, $3::jsonb, $4, $5)
             ON CONFLICT (tenant_id, version)
             DO UPDATE SET manifest = EXCLUDED.manifest,
                           signature = EXCLUDED.signature,
                           verified_at = EXCLUDED.verified_at,
                           imported_at = NOW()
           RETURNING id`,
          [authContext.tenantId, normalized.feedVersion, payload.manifest, signature, verifiedAt]
        );

        const insertedManifestId = manifestResult.rows[0]?.id ?? null;

        if (!insertedManifestId) {
          throw new Error('Feed manifest insert failed.');
        }

        await client.query('DELETE FROM feed_packages WHERE tenant_id = $1 AND manifest_id = $2', [
          authContext.tenantId,
          insertedManifestId
        ]);

        if (normalized.packages.length > 0) {
          const packageValues: unknown[] = [];
          const packageTuples: string[] = [];

          normalized.packages.forEach((pkg, index) => {
            packageValues.push(
              authContext.tenantId,
              insertedManifestId,
              pkg.filename,
              pkg.sha256,
              pkg.sizeBytes,
              pkg.storedAt
            );
            const offset = index * 6;
            packageTuples.push(
              `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, $${offset + 6})`
            );
          });

          await client.query(
            `INSERT INTO feed_packages (tenant_id, manifest_id, filename, sha256, size_bytes, stored_at)
               VALUES ${packageTuples.join(', ')}`,
            packageValues
          );
        }

        await client.query('DELETE FROM osv_cache WHERE tenant_id = $1 AND feed_version = $2', [
          authContext.tenantId,
          normalized.feedVersion
        ]);

        if (normalized.vulnerabilities.length > 0) {
          const vulnerabilityValues: unknown[] = [];
          const vulnerabilityTuples: string[] = [];

          normalized.vulnerabilities.forEach((entry, index) => {
            vulnerabilityValues.push(
              authContext.tenantId,
              entry.packagePurl,
              normalized.feedVersion,
              entry.vulnerabilities,
              entry.fetchedAt ?? now
            );
            const offset = index * 5;
            vulnerabilityTuples.push(
              `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5})`
            );
          });

          await client.query(
            `INSERT INTO osv_cache (tenant_id, package_purl, feed_version, vulnerabilities, fetched_at)
               VALUES ${vulnerabilityTuples.join(', ')}
               ON CONFLICT (tenant_id, package_purl, feed_version)
               DO UPDATE SET vulnerabilities = EXCLUDED.vulnerabilities, fetched_at = EXCLUDED.fetched_at`,
            vulnerabilityValues
          );
        }

        return insertedManifestId;
      });
    } catch (error) {
      request.log.error({ err: error }, 'Failed to store feed manifest.');
      return sendError(reply, request, 500, 'internal_error', 'Failed to store feed manifest.');
    }

    if (!manifestId) {
      return sendError(reply, request, 500, 'internal_error', 'Feed manifest persistence failed.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'feed.uploaded',
      payload: {
        manifest_id: manifestId,
        version: normalized.feedVersion,
        package_count: normalized.packages.length,
        vulnerability_count: normalized.vulnerabilities.length,
        signature_present: signature != null,
        signature_verified: verifiedAt != null
      }
    });

    metrics.feedImportCounter.inc({ action: 'upload' });

    await appendUpdateLog({
      action: 'feed.upload',
      manifest_id: manifestId,
      version: normalized.feedVersion,
      actor,
      result: 'success',
      metadata: {
        signature_present: signature != null,
        signature_verified: verifiedAt != null,
        minimum_downgrade_version: normalized.minimumDowngradeVersion
      }
    });

    return reply.status(201).send({
      manifest_id: manifestId,
      version: normalized.feedVersion,
      package_count: normalized.packages.length,
      vulnerability_count: normalized.vulnerabilities.length,
      signature_verified: verifiedAt != null
    });
  });

  app.get('/v1/feeds', async (request, reply) => {
    const parsed = listFeedsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;

    const manifestsResult = await db.query<{
      id: string;
      version: string;
      manifest: Record<string, unknown>;
      imported_at: Date | string;
      verified_at: Date | string | null;
      signature: string | null;
    }>(
      `SELECT id, version, manifest, imported_at, verified_at, signature
         FROM feed_manifests
        WHERE tenant_id = $1
        ORDER BY imported_at DESC
        LIMIT $2 OFFSET $3`,
      [authContext.tenantId, pageSize, offset]
    );

    const feedRows = manifestsResult.rows.map((row) => {
      let minimumDowngradeVersion: string | null = null;

      try {
        const normalized = parseFeedManifest(row.manifest);
        minimumDowngradeVersion = normalized.minimumDowngradeVersion;
      } catch (error) {
        app.log.warn({ err: error, manifest_id: row.id }, 'Failed to parse feed manifest while listing feeds');
      }

      return {
        ...row,
        minimum_downgrade_version: minimumDowngradeVersion
      };
    });

    const { activeVersion, minimumDowngradeVersion: activeMinimumDowngradeVersion } =
      await resolveActiveFeedState(authContext.tenantId);

    return reply.status(200).send({
      data: feedRows,
      pagination: { page, page_size: pageSize },
      active_version: activeVersion,
      active_minimum_downgrade_version: activeMinimumDowngradeVersion
    });
  });

  app.post('/v1/feeds/activate', async (request, reply) => {
    const parsed = manageFeedSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    const actor = `api_key:${authContext.apiKeyId ?? 'unknown'}`;

    if (payload.tenant_id !== authContext.tenantId) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: payload.version ?? null,
        actor,
        result: 'failure',
        metadata: { reason: 'tenant_mismatch' }
      });
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const { activeVersion, minimumDowngradeVersion: activeMinimumDowngradeVersion } =
      await resolveActiveFeedState(authContext.tenantId);

    const manifestResult = await db.query<{
      id: string;
      version: string;
      verified_at: Date | string | null;
      signature: string | null;
      manifest: Record<string, unknown>;
    }>(
      `SELECT id, version, verified_at, signature, manifest
         FROM feed_manifests
        WHERE id = $1 AND tenant_id = $2
        LIMIT 1`,
      [payload.manifest_id, authContext.tenantId]
    );

    const manifest = manifestResult.rows[0];

    if (!manifest) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: payload.version ?? null,
        actor,
        result: 'failure',
        metadata: { reason: 'manifest_not_found' }
      });
      return sendError(reply, request, 404, 'not_found', 'Feed manifest not found.');
    }

    if (payload.version && payload.version !== manifest.version) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: payload.version,
        actor,
        result: 'failure',
        metadata: { reason: 'version_mismatch', manifest_version: manifest.version }
      });
      return sendError(
        reply,
        request,
        400,
        'validation_error',
        'Manifest version mismatch. Please refresh feed list and retry.'
      );
    }

    const manifestVersion = manifest.version;
    const signaturePresent = manifest.signature != null;
    const signatureVerified = manifest.verified_at != null;

    if (!signaturePresent || !signatureVerified) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'signature_not_verified',
          signature_present: signaturePresent,
          signature_verified: signatureVerified
        }
      });
      await recordAuditEvent(db, {
        tenantId: authContext.tenantId,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'feed.activate_blocked',
        payload: {
          manifest_id: payload.manifest_id,
          version: manifestVersion,
          reason: 'signature_not_verified',
          manifest_signature_present: signaturePresent,
          manifest_signature_verified: signatureVerified
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Manifest signature must be verified before activation.'
      );
    }

    if (activeVersion && compareVersionStrings(manifestVersion, activeVersion) < 0) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'older_than_active_version',
          active_version: activeVersion,
          minimum_downgrade_version: activeMinimumDowngradeVersion
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Target version is older than the currently active feed. Use the rollback endpoint.'
      );
    }

    let targetMinimumDowngradeVersion: string | null = null;

    try {
      targetMinimumDowngradeVersion = parseFeedManifest(manifest.manifest).minimumDowngradeVersion;
    } catch (error) {
      app.log.warn({ err: error, manifestId: manifest.id }, 'Failed to parse feed manifest during activation');
    }

    if (!targetMinimumDowngradeVersion) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'minimum_downgrade_version_missing',
          active_minimum_downgrade_version: activeMinimumDowngradeVersion
        }
      });
      await recordAuditEvent(db, {
        tenantId: authContext.tenantId,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'feed.activate_blocked',
        payload: {
          manifest_id: payload.manifest_id,
          version: manifestVersion,
          reason: 'minimum_downgrade_version_missing',
          active_minimum_downgrade_version: activeMinimumDowngradeVersion
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Manifest must specify minimum_downgrade_version to allow controlled rollback.'
      );
    }

    if (
      activeMinimumDowngradeVersion &&
      compareVersionStrings(targetMinimumDowngradeVersion, activeMinimumDowngradeVersion) < 0
    ) {
      await appendUpdateLog({
        action: 'feed.activate',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'minimum_downgrade_version_lower_than_floor',
          target_minimum_downgrade_version: targetMinimumDowngradeVersion,
          active_minimum_downgrade_version: activeMinimumDowngradeVersion
        }
      });
      await recordAuditEvent(db, {
        tenantId: authContext.tenantId,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'feed.activate_blocked',
        payload: {
          manifest_id: payload.manifest_id,
          version: manifestVersion,
          reason: 'minimum_downgrade_version_lower_than_floor',
          target_minimum_downgrade_version: targetMinimumDowngradeVersion,
          active_minimum_downgrade_version: activeMinimumDowngradeVersion
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Manifest minimum_downgrade_version cannot be lower than the active downgrade floor.'
      );
    }

    try {
      await runInTransaction(db, async (client) => {
        await client.query(
          `UPDATE tenants
              SET metadata = jsonb_set(
                jsonb_set(metadata::jsonb, '{active_feed_version}', to_jsonb($2::text), true),
                '{minimum_downgrade_version}',
                CASE WHEN $3::text IS NULL THEN 'null'::jsonb ELSE to_jsonb($3::text) END,
                true
              )
            WHERE id = $1`,
          [authContext.tenantId, manifestVersion, targetMinimumDowngradeVersion]
        );
      });
    } catch (error) {
      request.log.error({ err: error, manifestId: payload.manifest_id }, 'Failed to activate feed manifest.');
      return sendError(reply, request, 500, 'internal_error', 'Failed to activate feed manifest.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'feed.activated',
      payload: {
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        manifest_signature_present: signaturePresent,
        manifest_signature_verified: signatureVerified
      }
    });

    metrics.feedImportCounter.inc({ action: 'activate' });

    await appendUpdateLog({
      action: 'feed.activate',
      manifest_id: payload.manifest_id,
      version: manifestVersion,
      actor,
      result: 'success',
      metadata: {
        signature_present: signaturePresent,
        signature_verified: signatureVerified,
        minimum_downgrade_version: targetMinimumDowngradeVersion
      }
    });

    return reply.status(204).send();
  });

  app.post('/v1/feeds/rollback', async (request, reply) => {
    const parsed = manageFeedSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin']);

    if (!authContext) {
      return;
    }

    const actor = `api_key:${authContext.apiKeyId ?? 'unknown'}`;

    if (payload.tenant_id !== authContext.tenantId) {
      await appendUpdateLog({
        action: 'feed.rollback',
        manifest_id: payload.manifest_id,
        version: payload.version ?? null,
        actor,
        result: 'failure',
        metadata: { reason: 'tenant_mismatch' }
      });
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const { activeVersion, minimumDowngradeVersion: activeMinimumDowngradeVersion } =
      await resolveActiveFeedState(authContext.tenantId);

    const manifestResult = await db.query<{
      id: string;
      version: string;
      verified_at: Date | string | null;
      signature: string | null;
      manifest: Record<string, unknown>;
    }>(
      `SELECT id, version, verified_at, signature, manifest
         FROM feed_manifests
        WHERE id = $1 AND tenant_id = $2
        LIMIT 1`,
      [payload.manifest_id, authContext.tenantId]
    );

    const manifest = manifestResult.rows[0];

    if (!manifest) {
      await appendUpdateLog({
        action: 'feed.rollback',
        manifest_id: payload.manifest_id,
        version: payload.version ?? null,
        actor,
        result: 'failure',
        metadata: { reason: 'manifest_not_found' }
      });
      return sendError(reply, request, 404, 'not_found', 'Feed manifest not found.');
    }

    if (payload.version && payload.version !== manifest.version) {
      await appendUpdateLog({
        action: 'feed.rollback',
        manifest_id: payload.manifest_id,
        version: payload.version,
        actor,
        result: 'failure',
        metadata: { reason: 'version_mismatch', manifest_version: manifest.version }
      });
      return sendError(
        reply,
        request,
        400,
        'validation_error',
        'Manifest version mismatch. Please refresh feed list and retry.'
      );
    }

    const manifestVersion = manifest.version;
    const signaturePresent = manifest.signature != null;
    const signatureVerified = manifest.verified_at != null;

    if (!signaturePresent || !signatureVerified) {
      await appendUpdateLog({
        action: 'feed.rollback',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'signature_not_verified',
          signature_present: signaturePresent,
          signature_verified: signatureVerified
        }
      });
      await recordAuditEvent(db, {
        tenantId: authContext.tenantId,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'feed.rollback_blocked',
        payload: {
          manifest_id: payload.manifest_id,
          version: manifestVersion,
          reason: 'signature_not_verified',
          manifest_signature_present: signaturePresent,
          manifest_signature_verified: signatureVerified
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Manifest signature must be verified before rollback.'
      );
    }

    if (activeVersion && compareVersionStrings(manifestVersion, activeVersion) > 0) {
      await appendUpdateLog({
        action: 'feed.rollback',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'newer_than_active_version',
          active_version: activeVersion
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Rollback target must not be newer than the currently active feed.'
      );
    }

    if (
      activeMinimumDowngradeVersion &&
      compareVersionStrings(manifestVersion, activeMinimumDowngradeVersion) < 0
    ) {
      await appendUpdateLog({
        action: 'feed.rollback',
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        actor,
        result: 'blocked',
        metadata: {
          reason: 'below_minimum_downgrade_version',
          minimum_downgrade_version: activeMinimumDowngradeVersion,
          active_version: activeVersion
        }
      });
      return sendError(
        reply,
        request,
        409,
        'conflict',
        'Target version is below the enforced minimum_downgrade_version for the active feed.'
      );
    }

    let targetMinimumDowngradeVersion: string | null = null;

    try {
      targetMinimumDowngradeVersion = parseFeedManifest(manifest.manifest).minimumDowngradeVersion;
    } catch (error) {
      app.log.warn({ err: error, manifestId: manifest.id }, 'Failed to parse feed manifest during rollback');
    }

    try {
      await runInTransaction(db, async (client) => {
        await client.query(
          `UPDATE tenants
              SET metadata = jsonb_set(
                jsonb_set(metadata::jsonb, '{active_feed_version}', to_jsonb($2::text), true),
                '{minimum_downgrade_version}',
                CASE WHEN $3::text IS NULL THEN 'null'::jsonb ELSE to_jsonb($3::text) END,
                true
              )
            WHERE id = $1`,
          [authContext.tenantId, manifestVersion, targetMinimumDowngradeVersion]
        );
      });
    } catch (error) {
      request.log.error({ err: error, manifestId: payload.manifest_id }, 'Failed to rollback feed manifest.');
      return sendError(reply, request, 500, 'internal_error', 'Failed to rollback feed manifest.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'feed.rollback',
      payload: {
        manifest_id: payload.manifest_id,
        version: manifestVersion,
        manifest_signature_present: signaturePresent,
        manifest_signature_verified: signatureVerified
      }
    });

    metrics.feedImportCounter.inc({ action: 'rollback' });

    await appendUpdateLog({
      action: 'feed.rollback',
      manifest_id: payload.manifest_id,
      version: manifestVersion,
      actor,
      result: 'success',
      metadata: {
        signature_present: signaturePresent,
        signature_verified: signatureVerified,
        minimum_downgrade_version: targetMinimumDowngradeVersion,
        active_version: activeVersion
      }
    });

    return reply.status(204).send();
  });

  app.post('/v1/integrations/artifact-gate', async (request, reply) => {
    const parsed = artifactGateRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const params: unknown[] = [payload.project_id, authContext.tenantId];
    let query =
      `SELECT s.id, s.policy_result, s.completed_at, s.findings
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
        WHERE s.project_id = $1
          AND p.tenant_id = $2
          AND s.status = 'succeeded'`;

    if (payload.artifact_id) {
      params.push(payload.artifact_id);
      query += ` AND s.artifact_id = $${params.length}`;
    }

    query += ' ORDER BY s.completed_at DESC NULLS LAST, s.created_at DESC LIMIT 1';

    const scanResult = await db.query<{
      id: string;
      policy_result: string;
      completed_at: Date | string | null;
      findings: Record<string, unknown> | null;
    }>(query, params);

    const scan = scanResult.rows[0] ?? null;
    let decision: 'allow' | 'deny' = 'deny';
    let reason: string | undefined;
    let policyResult: string | null = null;
    let scanId: string | null = null;
    let completedAt: string | null = null;
    let policyReasons: string[] = [];

    if (!scan) {
      reason = 'no_successful_scan';
    } else {
      policyResult = scan.policy_result;
      scanId = scan.id;
      completedAt = scan.completed_at ? new Date(scan.completed_at).toISOString() : null;
      if (policyResult === 'pass') {
        decision = 'allow';
      } else {
        decision = 'deny';
        reason = `latest_scan_${policyResult}`;
      }

      const findings = scan.findings;
      if (findings && typeof findings === 'object' && 'policy' in findings) {
        const policyFinding = (findings as { policy?: { reasons?: unknown } }).policy;
        if (policyFinding && Array.isArray(policyFinding.reasons)) {
          policyReasons = policyFinding.reasons.filter((value): value is string => typeof value === 'string');
        }
      }
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      projectId: payload.project_id,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'integration.artifact_gate',
      payload: {
        requested_by: payload.requested_by ?? null,
        artifact_name: payload.artifact_name,
        artifact_digest: payload.artifact_digest ?? null,
        decision,
        reason: reason ?? null,
        policy_result: policyResult,
        scan_id: scanId,
        policy_reasons: policyReasons
      }
    });

    const responseBody: {
      decision: 'allow' | 'deny';
      policy_result: string | null;
      scan_id: string | null;
      completed_at: string | null;
      policy_reasons: string[];
      reason?: string;
    } = {
      decision,
      policy_result: policyResult,
      scan_id: scanId,
      completed_at: completedAt,
      policy_reasons: policyReasons
    };

    if (reason) {
      responseBody.reason = reason;
    }

    return reply.status(200).send(responseBody);
  });

  app.get('/v1/vex', async (request, reply) => {
    const parsed = listVexQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin']);

    if (!authContext) {
      return;
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const vexResult = await db.query<{
      id: string;
      component_purl: string;
      advisory_id: string | null;
      status: string;
      justification: string | null;
      metadata: Record<string, unknown>;
      issued_at: Date | string;
      updated_at: Date | string;
    }>(
      `SELECT id, component_purl, advisory_id, status, justification, metadata, issued_at, updated_at
         FROM vex_statements
        WHERE tenant_id = $1 AND ($2::text IS NULL OR component_purl = $2)
        ORDER BY updated_at DESC`,
      [authContext.tenantId, query.component_purl ?? null]
    );

    return reply.status(200).send({ data: vexResult.rows });
  });

  app.post('/v1/vex', async (request, reply) => {
    const parsed = createVexSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const vexId = generateId();
    const metadata: Record<string, unknown> = payload.metadata ?? {};

    const result = await db.query(
      `INSERT INTO vex_statements (id, tenant_id, component_purl, advisory_id, status, justification, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, tenant_id, component_purl, advisory_id, status, justification, metadata, issued_at, updated_at`,
      [
        vexId,
        authContext.tenantId,
        payload.component_purl,
        payload.advisory_id ?? null,
        payload.status,
        payload.justification ?? null,
        metadata
      ]
    );

    const statement = result.rows[0];

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'vex.created',
      payload: statement
    });

    metrics.vexStateGauge.set(statement.status, 1);

    return reply.status(201).send({ data: statement });
  });

  app.put('/v1/vex/:id', async (request, reply) => {
    const paramsParsed = updateVexParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid request parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const bodyParsed = updateVexSchema.safeParse(request.body);

    if (!bodyParsed.success) {
      const message = bodyParsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const params = paramsParsed.data;
    const payload = bodyParsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const metadata: Record<string, unknown> = payload.metadata ?? {};

    const result = await db.query(
      `UPDATE vex_statements
          SET status = COALESCE($4, status),
              justification = COALESCE($5, justification),
              metadata = CASE WHEN $6::jsonb IS NULL THEN metadata ELSE $6::jsonb END,
              advisory_id = COALESCE($3, advisory_id),
              component_purl = COALESCE($2, component_purl),
              updated_at = NOW()
        WHERE id = $1 AND tenant_id = $7
        RETURNING id, tenant_id, component_purl, advisory_id, status, justification, metadata, issued_at, updated_at`,
      [
        params.id,
        payload.component_purl ?? null,
        payload.advisory_id ?? null,
        payload.status ?? null,
        payload.justification ?? null,
        Object.keys(metadata).length > 0 ? metadata : null,
        authContext.tenantId
      ]
    );

    const updated = result.rows[0];

    if (!updated) {
      return sendError(reply, request, 404, 'not_found', 'VEX statement not found.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'vex.updated',
      payload: updated
    });

    metrics.vexStateGauge.set(updated.status, 1);

    return reply.status(200).send({ data: updated });
  });

  app.delete('/v1/vex/:id', async (request, reply) => {
    const paramsParsed = updateVexParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid request parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const params = paramsParsed.data;
    const tenantId = request.body && typeof request.body.tenant_id === 'string'
      ? request.body.tenant_id
      : undefined;

    if (!tenantId) {
      return sendError(reply, request, 400, 'validation_error', 'tenant_id is required.');
    }

    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin']);

    if (!authContext) {
      return;
    }

    if (tenantId !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const existingResult = await db.query<{ status: string }>(
      'SELECT status FROM vex_statements WHERE id = $1 AND tenant_id = $2 LIMIT 1',
      [params.id, authContext.tenantId]
    );

    const existing = existingResult.rows[0];

    if (!existing) {
      return sendError(reply, request, 404, 'not_found', 'VEX statement not found.');
    }

    await db.query('DELETE FROM vex_statements WHERE id = $1 AND tenant_id = $2', [
      params.id,
      authContext.tenantId
    ]);

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'vex.deleted',
      payload: { statement_id: params.id }
    });

    metrics.vexStateGauge.set(existing.status, 0);

    return reply.status(204).send();
  });

  app.get('/v1/exceptions', async (request, reply) => {
    const parsed = listExceptionsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin', 'Legal']);

    if (!authContext) {
      return;
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const exceptionsResult = await db.query(
      `SELECT id, tenant_id, project_id, component_purl, scope, status, rationale, requested_by, approved_by,
              approval_notes, requested_at, approved_at, expires_at, metadata
         FROM policy_exceptions
        WHERE tenant_id = $1
          AND ($2::text IS NULL OR status = $2)
          AND ($3::text IS NULL OR scope = $3)
        ORDER BY requested_at DESC`,
      [authContext.tenantId, query.status ?? null, query.scope ?? null]
    );

    return reply.status(200).send({ data: exceptionsResult.rows });
  });

  app.post('/v1/exceptions', async (request, reply) => {
    const parsed = createExceptionSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin', 'Legal']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const exceptionId = generateId();
    const componentPurl = payload.scope === 'package' ? payload.component_purl ?? null : null;
    const projectId = payload.scope === 'organization' ? null : payload.project_id ?? null;
    const metadata = payload.metadata ?? {};
    const expiresAt = payload.expires_at ?? null;

    const result = await db.query(
      `INSERT INTO policy_exceptions (id, tenant_id, project_id, component_purl, scope, status, rationale, requested_by, expires_at, metadata)
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9)
         RETURNING id, tenant_id, project_id, component_purl, scope, status, rationale, requested_by, approved_by, approval_notes, requested_at, approved_at, expires_at, metadata`,
      [
        exceptionId,
        authContext.tenantId,
        projectId,
        componentPurl,
        payload.scope,
        payload.rationale ?? null,
        payload.requested_by,
        expiresAt,
        metadata
      ]
    );

    const exception = result.rows[0];

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'policy.exception.created',
      projectId,
      payload: exception
    });

    return reply.status(201).send({ data: exception });
  });

  app.put('/v1/exceptions/:id', async (request, reply) => {
    const paramsParsed = updateExceptionParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid request parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const bodyParsed = updateExceptionSchema.safeParse(request.body);

    if (!bodyParsed.success) {
      const message = bodyParsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const params = paramsParsed.data;
    const payload = bodyParsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Security', 'Admin', 'Legal']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const metadata = payload.metadata ?? {};
    const metadataParam = Object.keys(metadata).length > 0 ? metadata : null;
    const expiresAt = payload.expires_at ?? null;
    const approvalNotes = payload.approval_notes ?? null;
    const rationale = payload.rationale ?? null;
    const status = payload.status;
    const approvedBy = status === 'approved' || status === 'revoked' ? authContext.apiKeyId : null;

    const result = await db.query(
      `UPDATE policy_exceptions
          SET status = $3,
              expires_at = CASE WHEN $4::timestamptz IS NULL THEN expires_at ELSE $4 END,
              approval_notes = CASE WHEN $5 IS NULL THEN approval_notes ELSE $5 END,
              metadata = CASE WHEN $6::jsonb IS NULL THEN metadata ELSE $6::jsonb END,
              rationale = CASE WHEN $7 IS NULL THEN rationale ELSE $7 END,
              approved_by = CASE WHEN $3 IN ('approved', 'revoked') THEN $8 ELSE NULL END,
              approved_at = CASE WHEN $3 IN ('approved', 'revoked') THEN NOW() ELSE NULL END,
              updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        RETURNING id, tenant_id, project_id, component_purl, scope, status, rationale, requested_by, approved_by, approval_notes, requested_at, approved_at, expires_at, metadata`,
      [
        params.id,
        authContext.tenantId,
        status,
        expiresAt,
        approvalNotes,
        metadataParam,
        rationale,
        approvedBy
      ]
    );

    const exception = result.rows[0];

    if (!exception) {
      return sendError(reply, request, 404, 'not_found', 'Policy exception not found.');
    }

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'policy.exception.updated',
      projectId: exception.project_id ?? undefined,
      payload: {
        id: exception.id,
        status: exception.status,
        expires_at: exception.expires_at,
        approved_by: exception.approved_by,
        approval_notes: exception.approval_notes
      }
    });

    return reply.status(200).send({ data: exception });
  });

  app.get('/v1/scans/:id/evidence-pack', async (request, reply) => {
    const parsed = getScanParamsSchema.safeParse(request.params);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const params = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Auditor', 'Admin']);

    if (!authContext) {
      return;
    }

    const scanResult = await db.query<{ id: string; project_id: string }>(
      `SELECT s.id, s.project_id
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
        WHERE s.id = $1 AND p.tenant_id = $2
        LIMIT 1`,
      [params.id, authContext.tenantId]
    );

    const scan = scanResult.rows[0];

    if (!scan) {
      return sendError(reply, request, 404, 'not_found', 'Scan not found.');
    }

    const packResult = await db.query<{
      storage_path: string | null;
      manifest: Record<string, unknown>;
      signature: string | null;
      hash_algorithm: string | null;
    }>(
      `SELECT storage_path, manifest, signature, hash_algorithm
         FROM evidence_packs
        WHERE scan_id = $1 AND tenant_id = $2
        LIMIT 1`,
      [params.id, authContext.tenantId]
    );

    const pack = packResult.rows[0];

    if (!pack) {
      return sendError(reply, request, 404, 'not_found', 'Evidence pack not available.');
    }

    let archive: Buffer;

    const manifest = (pack.manifest ?? {}) as Record<string, unknown>;
    const noticeVersion = manifest['notice_version_id'];
    const manifestFeedVersion = manifest['feed_version'];

    if (typeof noticeVersion === 'string') {
      void reply.header('x-notice-version-id', noticeVersion);
    }

    if (typeof manifestFeedVersion === 'string') {
      void reply.header('x-feed-version', manifestFeedVersion);
    }

    if (pack.storage_path) {
      try {
        archive = await readFile(pack.storage_path);
      } catch (error) {
        request.log.error({ err: error }, 'Failed to read evidence pack archive.');
        return sendError(reply, request, 500, 'internal_error', 'Evidence pack is unavailable.');
      }
    } else if (typeof pack.manifest?.inline_data === 'string') {
      archive = Buffer.from(pack.manifest.inline_data, 'base64');
    } else {
      return sendError(reply, request, 500, 'internal_error', 'Evidence pack contents missing.');
    }

    void reply.header('content-type', 'application/zip');
    void reply.header('content-disposition', `attachment; filename="evidence-pack-${params.id}.zip"`);
    void reply.header('cache-control', 'no-store, private');
    void reply.header('pragma', 'no-cache');
    void reply.header('expires', '0');
    void reply.header('surrogate-control', 'no-store');

    return reply.status(200).send(archive);
  });

  const licenseStatusProvider =
    options.licenseStatusProvider ??
    (() =>
      getLicenseStatus({
        logger: (message: string) => {
          app.log.info({ event: 'license_status' }, message);
        },
        ...(resolvedLicensePublicKey ? { publicKey: resolvedLicensePublicKey } : {})
      }));

  const licenseStatus = await licenseStatusProvider().catch((error: unknown) => {
    app.log.error({ err: error }, 'Failed to validate runtime license.');
    throw new Error('API server requires an active license with scan:execute entitlement.');
  });

  if (licenseStatus.status !== 'active') {
    app.log.error(
      {
        license_id: licenseStatus.licenseId,
        status: licenseStatus.status,
        warnings: licenseStatus.warnings
      },
      'Runtime license is not active.'
    );
    throw new Error(`License ${licenseStatus.licenseId} is ${licenseStatus.status}; refusing to start API server.`);
  }

  if (!licenseStatus.features.includes(REQUIRED_SCAN_FEATURE)) {
    app.log.error(
      {
        license_id: licenseStatus.licenseId,
        features: licenseStatus.features
      },
      'Runtime license missing required scan entitlement.'
    );
    throw new Error(
      `License ${licenseStatus.licenseId} is missing required feature ${REQUIRED_SCAN_FEATURE}; refusing to start API server.`
    );
  }

  const db = options.db;
  const queue = options.queue;
  const generateId = options.generateId ?? randomUUID;
  const metrics = options.metrics ?? defaultMetrics;
  const redis = options.redis;
  const rateLimiter = options.rateLimiter ?? createRateLimiter(redis);
  const apiKeySalt = resolvedApiKeySalt;
  const baseLookupApiKey =
    options.lookupApiKey ??
    (async (tokenHash: string) => {
      const result = await db.query<ApiKeyRecord>(
        'SELECT id, tenant_id, permissions, token_hash FROM api_keys WHERE token_lookup_hash = $1 LIMIT 1',
        [tokenHash]
      );

      return result.rows[0] ?? null;
    });
  const lookupApiKey = wrapLookupWithCache(baseLookupApiKey);
  const unauthorizedMessage = 'Missing or invalid API key.';
  const tenantScopeMessage = 'Tenant scope mismatch.';

  await app.register(swagger, {
    openapi: {
      info: {
        title: 'OSS Uyumluluk API',
        description: 'Otomatik OSS Lisans & Güvenlik Açığı Uyumluluk servisi',
        version: options.version
      },
      servers: [
        { url: '/v1' }
      ]
    }
  });

  await app.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list'
    }
  });

  registerHealthRoute(app, {
    version: options.version,
    db,
    queue,
    redis,
    metrics
  });

  const healthPanelUrl = new URL('../../web/health.html', import.meta.url);
  const cacheHealthPanel = (process.env.NODE_ENV ?? '') !== 'development';
  const loadHealthPanelHtml =
    options.loadHealthPanelHtml ?? (() => readFile(healthPanelUrl, 'utf-8'));
  let cachedHealthPanelHtml: string | null = null;

  app.get('/health/panel', async (request, reply) => {
    try {
      let html: string;

      if (cacheHealthPanel && cachedHealthPanelHtml !== null) {
        html = cachedHealthPanelHtml;
      } else {
        html = await loadHealthPanelHtml();
        if (cacheHealthPanel) {
          cachedHealthPanelHtml = html;
        }
      }

      void reply.header('content-type', 'text/html; charset=utf-8');
      return reply.send(html);
    } catch (error) {
      request.log.error({ err: error }, 'Failed to load health panel.');
      return sendError(reply, request, 500, 'internal_error', 'Health panel is unavailable.');
    }
  });

  app.addHook('onRequest', async (request, reply) => {
    if (!shouldAuthenticate(request)) {
      return;
    }

    const token = extractBearerToken(request.headers.authorization);

    if (!token) {
      await sendError(reply, request, 401, 'unauthorized', unauthorizedMessage);
      return;
    }

    const lookupHash = computeApiKeyLookupHash(token, apiKeySalt);
    const apiKey = await lookupApiKey(lookupHash);

    if (!apiKey) {
      await sendError(reply, request, 401, 'unauthorized', unauthorizedMessage);
      return;
    }

    const valid = await verifyApiKeyDigest(apiKey, lookupHash, { db, logger: request.log });

    if (!valid) {
      await sendError(reply, request, 401, 'unauthorized', unauthorizedMessage);
      return;
    }

    const roles = normalizeRoles(apiKey.permissions);

    request.authContext = {
      apiKeyId: apiKey.id,
      tenantId: apiKey.tenant_id,
      roles: roles.length > 0 ? roles : ['Developer']
    };

    const now = new Date();
    const rateLimitResult = await rateLimiter(apiKey.id, now);

    for (const entry of rateLimitResult.entries) {
      void reply.header(`X-RateLimit-Limit-${entry.scope}`, entry.limit.toString());
      void reply.header(`X-RateLimit-Remaining-${entry.scope}`, entry.remaining.toString());
      void reply.header(`X-RateLimit-Reset-${entry.scope}`, entry.resetSeconds.toString());
    }

    if (rateLimitResult.blocked) {
      const retryAfter = Math.max(rateLimitResult.blocked.resetSeconds, 0);
      void reply.header('Retry-After', retryAfter.toString());

      return sendError(reply, request, 429, 'rate_limit_exceeded', 'Rate limit exceeded.', {
        scope: rateLimitResult.blocked.scope,
        limit: rateLimitResult.blocked.limit,
        remaining: rateLimitResult.blocked.remaining,
        reset_seconds: rateLimitResult.blocked.resetSeconds
      });
    }
  });

  app.get('/', () => ({ message: 'OSS Uyumluluk servisi çalışıyor.' }));

  const ssoHandlers = options.ssoHandlers ?? {};

  if (ssoHandlers.saml) {
    app.post('/v1/auth/sso/saml', async (request, reply) => {
      try {
        const result = await ssoHandlers.saml({ request, payload: request.body });

        await recordAuditEvent(db, {
          tenantId: result.tenantId,
          actorType: 'sso',
          actorIdentifier: result.subject,
          eventType: 'sso.login',
          payload: {
            provider: 'saml',
            roles: result.roles
          }
        });

        return reply.status(200).send({
          data: {
            tenant_id: result.tenantId,
            api_key_id: result.apiKeyId,
            roles: result.roles
          }
        });
      } catch (error) {
        request.log.error({ err: error }, 'SAML SSO handler failed.');
        return sendError(reply, request, 401, 'unauthorized', 'SSO verification failed.');
      }
    });
  }

  if (ssoHandlers.oidc) {
    app.post('/v1/auth/sso/oidc', async (request, reply) => {
      try {
        const result = await ssoHandlers.oidc({ request, payload: request.body });

        await recordAuditEvent(db, {
          tenantId: result.tenantId,
          actorType: 'sso',
          actorIdentifier: result.subject,
          eventType: 'sso.login',
          payload: {
            provider: 'oidc',
            roles: result.roles
          }
        });

        return reply.status(200).send({
          data: {
            tenant_id: result.tenantId,
            api_key_id: result.apiKeyId,
            roles: result.roles
          }
        });
      } catch (error) {
        request.log.error({ err: error }, 'OIDC SSO handler failed.');
        return sendError(reply, request, 401, 'unauthorized', 'SSO verification failed.');
      }
    });
  }

  const createProjectSchema = z
    .object({
      tenant_id: z.string().uuid(),
      name: z.string().min(1),
      description: z.string().optional(),
      repo_url: z.string().min(1).optional(),
      oci_ref: z.string().min(1).optional(),
      metadata: z.record(z.unknown()).optional()
    })
    .superRefine((value, ctx) => {
      if (!value.repo_url && !value.oci_ref) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Either repo_url or oci_ref must be provided.'
        });
      }
    });

  const listProjectsQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20)
  });

  const listWebhooksQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20),
    event: z.string().min(1).optional()
  });

  const getProjectParamsSchema = z.object({
    id: z.string().uuid()
  });

  const getProjectQuerySchema = z.object({
    tenant_id: z.string().uuid().optional()
  });

  const createArtifactSchema = artifactDetailsSchema.extend({
    project_id: z.string().uuid()
  });

  function normalizeString(value: unknown): string | undefined {
    if (typeof value !== 'string') {
      return undefined;
    }

    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  function setIfDefined<T extends object>(target: T, key: keyof T, value: unknown): void {
    if (value !== undefined) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (target as any)[key] = value;
    }
  }

  function validateArtifactDetails(detail: ArtifactDetails): string | undefined {
    if (detail.type === 'git') {
      const commit = normalizeString(detail.ref.commit);
      const branch = normalizeString(detail.ref.branch);
      const url = normalizeString(detail.ref.url);

      if (!commit && !branch) {
        return 'Git artifacts require a commit or branch reference.';
      }

      if (!url) {
        return 'Git artifacts require a url reference.';
      }

      const isAllowedGitUrl =
        url.startsWith('https://') ||
        url.startsWith('ssh://') ||
        url.startsWith('git+ssh://') ||
        /^[^@]+@[^:]+:.+/u.test(url);

      if (!isAllowedGitUrl) {
        return 'Git artifacts require an https or ssh url reference.';
      }

      setIfDefined(detail.ref, 'commit', commit);
      setIfDefined(detail.ref, 'branch', branch);
      setIfDefined(detail.ref, 'url', url);
    }

    if (detail.type === 'archive') {
      const url = normalizeString(detail.ref.url);
      const sha256 = normalizeString(detail.ref.sha256);

      if (!url || !/^https:\/\//u.test(url)) {
        return 'Archive artifacts require an https url reference.';
      }

      if (!sha256) {
        return 'Archive artifacts require a sha256 digest reference.';
      }

      if (!/^[a-f0-9]{64}$/u.test(sha256)) {
        return 'Archive artifact sha256 digests must be 64 lowercase hex characters.';
      }

      setIfDefined(detail.ref, 'url', url);
      setIfDefined(detail.ref, 'sha256', sha256);
    }

    if (detail.type === 'oci') {
      const digest = normalizeString(detail.ref.digest);
      const tag = normalizeString(detail.ref.tag);
      const registry = normalizeString(detail.ref.registry);
      const repository = normalizeString(detail.ref.repository);

      if (!registry || !repository) {
        return 'OCI artifacts require registry and repository references.';
      }

      if (!digest && !tag) {
        return 'OCI artifacts require a digest or tag reference.';
      }

      setIfDefined(detail.ref, 'digest', digest);
      setIfDefined(detail.ref, 'tag', tag);
      setIfDefined(detail.ref, 'registry', registry);
      setIfDefined(detail.ref, 'repository', repository);
    }

    return undefined;
  }

  const createScanSchema = z
    .object({
      project_id: z.string().uuid(),
      artifact_id: z.string().uuid().optional(),
      artifact: artifactDetailsSchema.optional(),
      policy_id: z.string().uuid().optional()
    })
    .superRefine((value, ctx) => {
      if (value.artifact_id && value.artifact) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Provide either artifact_id or artifact, but not both.'
        });
      }
    });

  const artifactGateRequestSchema = z.object({
    tenant_id: z.string().uuid(),
    project_id: z.string().uuid(),
    artifact_id: z.string().uuid().optional().nullable(),
    artifact_name: z.string().min(1),
    artifact_digest: z.string().min(1).optional().nullable(),
    requested_by: z.string().min(1).optional().nullable()
  });

  const importSbomSchema = z.object({
    tenant_id: z.string().uuid(),
    project_id: z.string().uuid(),
    artifact_id: z.string().uuid().optional().nullable(),
    policy_id: z.string().uuid().optional().nullable(),
    format: z
      .string()
      .min(1, 'SBOM format is required.')
      .transform((value) => value.trim())
      .refine(
        (value) => {
          const normalized = value.toLowerCase();
          return normalized === 'cyclonedx' || normalized === 'spdx';
        },
        'SBOM format must be CycloneDX or SPDX.'
      )
      .transform((value) => (value.toLowerCase() === 'cyclonedx' ? 'CycloneDX' : 'SPDX')),
    sbom: z.object({}).passthrough(),
    metadata: z.record(z.unknown()).optional()
  });

  const usageMetricsQuerySchema = z.object({
    days: z.coerce.number().int().min(1).max(90).default(30)
  });

  const listScansQuerySchema = z.object({
    project_id: z.string().uuid().optional(),
    status: z.string().min(1).optional(),
    policy_result: z.string().min(1).optional(),
    created_from: z.coerce.date().optional(),
    created_to: z.coerce.date().optional(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20)
  });

  const getScanParamsSchema = z.object({
    id: z.string().uuid()
  });

  const getSbomParamsSchema = z.object({
    scan_id: z.string().uuid()
  });

  const listLicensesQuerySchema = z.object({
    scan_id: z.string().uuid().optional(),
    spdx_id: z.string().min(1).optional(),
    component_purl: z.string().min(1).optional(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20)
  });

  const listVulnsQuerySchema = z.object({
    scan_id: z.string().uuid().optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'none', 'unknown']).optional(),
    component_purl: z.string().min(1).optional(),
    cvss_min: z.coerce.number().min(0).max(10).optional(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20)
  });
  const auditEventsQuerySchema = z
    .object({
      from: z.coerce.date().optional(),
      to: z.coerce.date().optional(),
      event_type: z.string().min(1).optional(),
      project_id: z.string().uuid().optional(),
      actor: z.string().min(1).optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50),
      cursor: z.string().min(1).optional(),
      format: z.enum(['json', 'jsonl']).optional()
    })
    .superRefine((value, ctx) => {
      if (value.from && value.to && value.from > value.to) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['to'],
          message: 'End date must be after the start date.'
        });
      }
    });
  const reportsSummaryQuerySchema = z.object({
    project_id: z.string().uuid().optional(),
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional()
  });
  const changesQuerySchema = z.object({
    since: z.coerce.date(),
    type: z.enum(['scan.completed', 'scan.failed']).optional()
  });

  const EMPTY_POLICY_RULES: PolicyRules = {
    allowed_spdx: [],
    denied_spdx: [],
    cvss_threshold: null,
    allowlists: {
      licenses: [],
      vulnerabilities: []
    }
  };

  const opaMatchSchema = z
    .object({
      component_purl: z.string().min(1).optional(),
      spdx: z.string().min(1).optional(),
      cve: z.string().min(1).optional()
    })
    .strip();

  const opaDecisionSchema = z
    .object({
      match: opaMatchSchema.optional(),
      effect: z.enum(['allow', 'deny']).optional(),
      reason: z.string().min(1).optional()
    })
    .strip();

  const opaRulesSchema = z
    .object({
      bundle_url: z.string().optional(),
      decisions: z.array(opaDecisionSchema).optional(),
      cache_ttl_seconds: z.coerce.number().int().positive().optional()
    })
    .strip()
    .superRefine((candidate, ctx) => {
      if (candidate.bundle_url === undefined) {
        return;
      }

      const trimmed = candidate.bundle_url.trim();

      if (!trimmed) {
        candidate.bundle_url = undefined;
        return;
      }

      let parsed: URL;

      try {
        parsed = new URL(trimmed);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['bundle_url'],
          message: 'OPA bundle_url must be a valid HTTPS URL.'
        });
        return;
      }

      if (parsed.protocol !== 'https:') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['bundle_url'],
          message: 'OPA bundle_url must use HTTPS.'
        });
        return;
      }

      parsed.username = '';
      parsed.password = '';
      candidate.bundle_url = parsed.toString();
    });

  const policyRulesSchema = z
    .object({
      allowed_spdx: z.array(z.string().min(1)).optional(),
      denied_spdx: z.array(z.string().min(1)).optional(),
      cvss_threshold: z.number().min(0).max(10).optional(),
      allowlists: z
        .object({
          licenses: z.array(z.string().min(1)).optional(),
          vulnerabilities: z.array(z.string().min(1)).optional()
        })
        .optional(),
      opa: opaRulesSchema.optional()
    })
    .strip()
    .transform((value) => {
      const sanitizedDecisions = (value.opa?.decisions ?? [])
        .map((decision) => {
          const normalizedMatch = decision.match
            ? {
                ...(decision.match.component_purl
                  ? { component_purl: decision.match.component_purl }
                  : {}),
                ...(decision.match.spdx ? { spdx: decision.match.spdx } : {}),
                ...(decision.match.cve ? { cve: decision.match.cve } : {})
              }
            : undefined;

          const normalized: Record<string, unknown> = {};

          if (normalizedMatch && Object.keys(normalizedMatch).length > 0) {
            normalized.match = normalizedMatch;
          }

          if (decision.effect) {
            normalized.effect = decision.effect;
          }

          if (decision.reason) {
            normalized.reason = decision.reason;
          }

          return normalized;
        })
        .filter((decision) => Object.keys(decision).length > 0);

      const sanitizedOpa = value.opa
        ? (() => {
            const payload: Record<string, unknown> = {};

            if (value.opa?.bundle_url) {
              payload.bundle_url = value.opa.bundle_url;
            }

            if (sanitizedDecisions.length > 0) {
              payload.decisions = sanitizedDecisions;
            }

            if (typeof value.opa?.cache_ttl_seconds === 'number') {
              payload.cache_ttl_seconds = value.opa.cache_ttl_seconds;
            }

            return Object.keys(payload).length > 0 ? (payload as PolicyRules['opa']) : undefined;
          })()
        : undefined;

      const normalized: PolicyRules = {
        allowed_spdx: value.allowed_spdx ?? [],
        denied_spdx: value.denied_spdx ?? [],
        cvss_threshold: typeof value.cvss_threshold === 'number' ? value.cvss_threshold : null,
        allowlists: {
          licenses: value.allowlists?.licenses ?? [],
          vulnerabilities: value.allowlists?.vulnerabilities ?? []
        }
      };

      if (sanitizedOpa) {
        normalized.opa = sanitizedOpa;
      }

      return normalized;
    });

  const createPolicySchema = z.object({
    tenant_id: z.string().uuid(),
    name: z.string().min(1),
    description: z.string().optional(),
    rules: policyRulesSchema
  });

  const getPolicyParamsSchema = z.object({
    id: z.string().uuid()
  });

  function normalizePolicyRow(row: PolicyRow): PolicyResponse {
    const parsed = policyRulesSchema.safeParse(row.rules ?? {});
    const rules = parsed.success ? parsed.data : EMPTY_POLICY_RULES;

    return {
      ...row,
      rules
    };
  }

  const httpsWebhookUrlSchema = z
    .string()
    .url()
    .refine((value) => {
      try {
        const url = new URL(value);
        return url.protocol === 'https:';
      } catch {
        return false;
      }
    }, 'Webhook URL must use HTTPS.');

  const createWebhookSchema = z.object({
    tenant_id: z.string().uuid(),
    url: httpsWebhookUrlSchema,
    secret: z.string().min(8).optional(),
    events: z.array(z.string().min(1)).min(1)
  });

  const createLegalDecisionSchema = z.object({
    tenant_id: z.string().uuid(),
    finding_id: z.string().uuid(),
    decision: z.enum(['allow', 'deny', 'conditional']),
    rationale: z.string().min(1).optional(),
    expires_at: z.string().datetime().optional(),
    metadata: z.record(z.unknown()).optional(),
    signoff: z
      .object({
        signer_name: z.string().min(1),
        signer_email: z.string().email().optional(),
        signature: z.string().min(1),
        payload: z.record(z.unknown()).optional()
      })
      .optional()
  });

  const listLegalFindingsQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    status: z.enum(['pending', 'allow', 'deny', 'conditional']).optional(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20)
  });

  const buildNoticeSchema = z.object({
    tenant_id: z.string().uuid(),
    project_id: z.string().uuid(),
    scan_id: z.string().uuid().optional(),
    template: z.string().min(1).default('default'),
    finalize: z.boolean().optional(),
    additional_text: z.string().optional(),
    signoff: z
      .object({
        signer_name: z.string().min(1),
        signer_email: z.string().email().optional(),
        signature: z.string().min(1),
        payload: z.record(z.unknown()).optional()
      })
      .optional()
  });

  const roleEnum = z.enum(['Admin', 'Security', 'Legal', 'Developer', 'Auditor']);

  const listApiKeysQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(20)
  });

  const createApiKeySchema = z.object({
    tenant_id: z.string().uuid(),
    name: z.string().min(1),
    roles: z.array(roleEnum).min(1).default(['Developer'])
  });

  const deleteApiKeyParamsSchema = z.object({
    id: z.string().uuid()
  });

  const deleteApiKeySchema = z.object({
    tenant_id: z.string().uuid()
  });

  const listFeedsQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    page: z.coerce.number().int().min(1).default(1),
    page_size: z.coerce.number().int().min(1).max(200).default(50)
  });

  const uploadFeedSchema = z.object({
    tenant_id: z.string().uuid(),
    version: z.string().min(1),
    manifest: z.record(z.unknown()),
    signature: z.string().min(1).optional().nullable()
  });

  const manageFeedSchema = z.object({
    tenant_id: z.string().uuid(),
    manifest_id: z.string().uuid(),
    version: z.string().min(1).optional()
  });

  const createVexSchema = z.object({
    tenant_id: z.string().uuid(),
    component_purl: z.string().min(1),
    advisory_id: z.string().min(1).optional(),
    status: z.enum(['not_affected', 'affected', 'fixed', 'under_investigation', 'unknown']),
    justification: z.string().optional(),
    metadata: z.record(z.unknown()).optional()
  });

  const updateVexParamsSchema = z.object({
    id: z.string().uuid()
  });

  const updateVexSchema = createVexSchema.partial().extend({ tenant_id: z.string().uuid() });

  const listVexQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    component_purl: z.string().min(1).optional()
  });

  const exceptionScopeSchema = z.enum(['package', 'project', 'organization']);

  const listExceptionsQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    status: z.enum(['pending', 'approved', 'revoked', 'expired']).optional(),
    scope: exceptionScopeSchema.optional()
  });

  const createExceptionSchema = z
    .object({
      tenant_id: z.string().uuid(),
      project_id: z.string().uuid().optional(),
      component_purl: z.string().min(1).optional(),
      scope: exceptionScopeSchema,
      rationale: z.string().min(1).optional(),
      requested_by: z.string().min(1),
      expires_at: z.string().datetime().optional(),
      metadata: z.record(z.unknown()).optional()
    })
    .refine((payload) => {
      if (payload.scope === 'package') {
        return Boolean(payload.component_purl);
      }

      if (payload.scope === 'project') {
        return Boolean(payload.project_id);
      }

      return true;
    }, 'Scope selection requires matching identifiers.');

  const updateExceptionParamsSchema = z.object({
    id: z.string().uuid()
  });

  const updateExceptionSchema = z
    .object({
      tenant_id: z.string().uuid(),
      status: z.enum(['pending', 'approved', 'revoked', 'expired']),
      rationale: z.string().min(1).optional(),
      expires_at: z.string().datetime().optional(),
      approval_notes: z.string().optional(),
      metadata: z.record(z.unknown()).optional()
    })
    .refine((payload) => payload.status !== 'expired', 'Status transitions to expired are automatic.');

  app.post('/v1/projects', async (request, reply) => {
    const parsed = createProjectSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin', 'Developer']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;
    const projectId = generateId();
    const metadata: Record<string, unknown> = payload.metadata ?? {};

    try {
      const result = await db.query<ProjectRow>(
        `INSERT INTO projects (id, tenant_id, name, description, repo_url, oci_ref, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, tenant_id, name, description, repo_url, oci_ref, metadata, created_at, updated_at`,
        [
          projectId,
          tenantId,
          payload.name,
          payload.description ?? null,
          payload.repo_url ?? null,
          payload.oci_ref ?? null,
          metadata
        ]
      );

      const project = result.rows[0];

      await recordAuditEvent(db, {
        tenantId,
        projectId: project.id,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'project.created',
        payload: {
          project_id: project.id,
          name: project.name,
          repo_url: project.repo_url,
          oci_ref: project.oci_ref,
          metadata
        }
      });

      return reply.status(201).send({ data: project });
    } catch (error: unknown) {
      const dbError = error as DatabaseError;

      if (dbError.code === '23505') {
        return sendError(reply, request, 409, 'conflict', 'A project with that name already exists.');
      }

      throw error;
    }
  });

  app.get('/v1/legal/findings', async (request, reply) => {
    const parsed = listLegalFindingsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Legal', 'Admin']);

    if (!authContext) {
      return;
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;
    const statusFilter = query.status ?? 'pending';

    const findingsResult = await db.query<
      LegalFindingRow & {
        decision: string | null;
        decided_at: Date | string | null;
        rationale: string | null;
      }
    >(
      `SELECT lf.id, lf.tenant_id, lf.license_id, lf.vuln_id, lf.scan_id, lf.status, lf.obligations, lf.notes, lf.created_at,
              ld.decision, ld.decided_at, ld.rationale
         FROM legal_findings lf
         LEFT JOIN LATERAL (
           SELECT decision, decided_at, rationale
             FROM legal_decisions
            WHERE finding_id = lf.id
            ORDER BY decided_at DESC
            LIMIT 1
         ) ld ON TRUE
        WHERE lf.tenant_id = $1 AND ($2::text IS NULL OR lf.status = $2)
        ORDER BY lf.created_at DESC
        LIMIT $3 OFFSET $4`,
      [authContext.tenantId, statusFilter, pageSize, offset]
    );

    return reply.status(200).send({
      data: findingsResult.rows.map((row) => ({
        id: row.id,
        status: row.status,
        obligations: row.obligations,
        notes: row.notes,
        scan_id: row.scan_id,
        license_id: row.license_id,
        decision: row.decision,
        decided_at: row.decided_at,
        rationale: row.rationale,
        created_at: row.created_at
      })),
      pagination: {
        page,
        page_size: pageSize
      }
    });
  });

  app.post('/v1/legal/decisions', async (request, reply) => {
    const parsed = createLegalDecisionSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const endNoticeTimer = metrics.noticeBuildHistogram.startTimer();
    const authContext = await ensureRoleAccess(request, reply, ['Legal', 'Admin']);

    if (!authContext) {
      endNoticeTimer({ outcome: 'error' });
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      endNoticeTimer({ outcome: 'error' });
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;

    const findingResult = await db.query<{ id: string; scan_id: string | null; project_id: string | null }>(
      `SELECT lf.id, lf.scan_id, s.project_id
         FROM legal_findings lf
         LEFT JOIN scans s ON s.id = lf.scan_id
         WHERE lf.id = $1 AND lf.tenant_id = $2
         LIMIT 1`,
      [payload.finding_id, tenantId]
    );

    const finding = findingResult.rows[0];

    if (!finding) {
      return sendError(reply, request, 404, 'not_found', 'Finding not found.');
    }

    const metadata: Record<string, unknown> = payload.metadata ?? {};
    const decisionId = generateId();
    const expiresAt = payload.expires_at ?? null;

    const decisionResult = await db.query<LegalDecisionRow>(
      `INSERT INTO legal_decisions (id, tenant_id, finding_id, decision, rationale, decided_by, expires_at, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, tenant_id, finding_id, decision, rationale, decided_by, decided_at, expires_at, metadata`,
      [
        decisionId,
        tenantId,
        payload.finding_id,
        payload.decision,
        payload.rationale ?? null,
        authContext.apiKeyId,
        expiresAt,
        metadata
      ]
    );

    const decision = decisionResult.rows[0];

    await db.query('UPDATE legal_findings SET status = $2 WHERE id = $1', [payload.finding_id, payload.decision]);

    let signoff: LegalSignoffRow | null = null;

    if (payload.signoff) {
      const signaturePayload = payload.signoff.payload ?? {};
      const signatureHash = createHash('sha256')
        .update(payload.signoff.signature)
        .digest('hex');
      const signoffId = generateId();

      const signoffResult = await db.query<LegalSignoffRow>(
        `INSERT INTO legal_signoffs (id, tenant_id, decision_id, signer_name, signer_email, signature_hash, signature_payload)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, tenant_id, decision_id, signer_name, signer_email, signature_hash, signature_payload, signed_at`,
        [
          signoffId,
          tenantId,
          decision.id,
          payload.signoff.signer_name,
          payload.signoff.signer_email ?? null,
          signatureHash,
          signaturePayload
        ]
      );

      signoff = signoffResult.rows[0];
    }

    await recordAuditEvent(db, {
      tenantId,
      projectId: finding.project_id,
      scanId: finding.scan_id,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'legal.decision.recorded',
      payload: {
        decision_id: decision.id,
        finding_id: payload.finding_id,
        decision: payload.decision,
        rationale: payload.rationale ?? null,
        expires_at: expiresAt,
        metadata,
        signoff: signoff
          ? {
              signer_name: signoff.signer_name,
              signer_email: signoff.signer_email,
              signature_hash: signoff.signature_hash
            }
          : null
      }
    });

    return reply.status(201).send({
      data: {
        decision,
        signoff
      }
    });
  });

  app.post('/v1/notice/build', async (request, reply) => {
    const parsed = buildNoticeSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const endNoticeTimer = metrics.noticeBuildHistogram.startTimer();
    const authContext = await ensureRoleAccess(request, reply, ['Legal', 'Admin']);

    if (!authContext) {
      endNoticeTimer({ outcome: 'error' });
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      endNoticeTimer({ outcome: 'error' });
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;

    const projectResult = await db.query<{ id: string; name: string }>(
      'SELECT id, name FROM projects WHERE id = $1 AND tenant_id = $2 LIMIT 1',
      [payload.project_id, tenantId]
    );

    const project = projectResult.rows[0];

    if (!project) {
      return sendError(reply, request, 404, 'not_found', 'Project not found.');
    }

    const licenseRows = await db.query<{
      component_purl: string;
      detected_spdx_id: string | null;
      decision: string | null;
    }>(
      `SELECT l.component_purl, l.detected_spdx_id, ld.decision
         FROM licenses l
         INNER JOIN sboms s ON s.id = l.sbom_id
         INNER JOIN projects p ON p.id = s.project_id
         LEFT JOIN legal_findings lf ON lf.license_id = l.id AND lf.tenant_id = $1
         LEFT JOIN LATERAL (
           SELECT decision
             FROM legal_decisions
            WHERE finding_id = lf.id
            ORDER BY decided_at DESC
            LIMIT 1
         ) ld ON TRUE
        WHERE p.id = $2 AND p.tenant_id = $1 AND ($3::uuid IS NULL OR s.scan_id = $3)
        ORDER BY l.component_purl ASC`,
      [tenantId, project.id, payload.scan_id ?? null]
    );

    const components = licenseRows.rows.map((row) => ({
      component_purl: row.component_purl,
      detected_spdx_id: row.detected_spdx_id,
      decision: row.decision ?? 'pending'
    }));

    const approved = components.filter((component) =>
      component.decision === 'allow' || component.decision === 'conditional'
    );

    const noticeLines: string[] = [
      `NOTICE for ${project.name}`,
      ''
    ];

    for (const entry of approved) {
      const license = entry.detected_spdx_id ?? 'UNKNOWN';
      noticeLines.push(`${entry.component_purl} — ${license}`);
    }

    if (approved.length === 0) {
      noticeLines.push('No approved components available.');
    }

    if (payload.additional_text) {
      noticeLines.push('', payload.additional_text);
    }

    const document = noticeLines.join('\n');
    let noticeVersionId: string | null = null;
    let feedVersion: string | null = null;

    let noticeSummary: Record<string, unknown> = {
      template: payload.template,
      component_count: approved.length,
      finalized: false,
      version_id: null
    };

    if (!payload.finalize && payload.scan_id) {
      await db.query(
        `UPDATE scans
            SET findings = jsonb_set(findings::jsonb, '{notice}', $3::jsonb, true)
          WHERE id = $1 AND project_id = $2`,
        [payload.scan_id, project.id, noticeSummary]
      );
    }

    if (payload.finalize) {
      if (!payload.signoff) {
        endNoticeTimer({ outcome: 'error' });
        return sendError(reply, request, 400, 'validation_error', 'Finalization requires a signoff payload.');
      }

      const signaturePayload = payload.signoff.payload ?? {};
      const signatureHash = createHash('sha256')
        .update(payload.signoff.signature)
        .digest('hex');

      const tenantMetadataResult = await db.query<{ metadata: Record<string, unknown> }>(
        'SELECT metadata FROM tenants WHERE id = $1 LIMIT 1',
        [tenantId]
      );

      const tenantMetadata = tenantMetadataResult.rows[0]?.metadata ?? {};
      const candidateFeedVersion =
        tenantMetadata && typeof tenantMetadata === 'object'
          ? (tenantMetadata as Record<string, unknown>).active_feed_version
          : null;

      if (typeof candidateFeedVersion === 'string') {
        feedVersion = candidateFeedVersion;
      }

      const noticeVersionResult = await db.query<{ id: string }>(
        `INSERT INTO notice_versions (tenant_id, project_id, scan_id, template, document, component_count, signature_hash, signoff_name, signoff_email, signoff_payload, feed_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id`,
        [
          tenantId,
          project.id,
          payload.scan_id ?? null,
          payload.template,
          document,
          approved.length,
          signatureHash,
          payload.signoff.signer_name,
          payload.signoff.signer_email ?? null,
          signaturePayload,
          feedVersion
        ]
      );

      noticeVersionId = noticeVersionResult.rows[0]?.id ?? null;

      noticeSummary = {
        template: payload.template,
        component_count: approved.length,
        finalized: true,
        version_id: noticeVersionId
      } satisfies Record<string, unknown>;

      if (payload.scan_id && noticeVersionId) {
        await db.query(
          `UPDATE scans
              SET findings = jsonb_set(
                    jsonb_set(findings::jsonb, '{notice}', $3::jsonb, true),
                    '{notice_version_id}',
                    to_jsonb($4::text),
                    true
                  )
            WHERE id = $1 AND project_id = $2`,
          [payload.scan_id, project.id, noticeSummary, noticeVersionId]
        );

        await db.query(
          `UPDATE evidence_packs
              SET manifest = jsonb_set(
                    jsonb_set(manifest::jsonb, '{notice_version_id}', to_jsonb($3::text), true),
                    '{notice_summary}',
                    to_jsonb($4::jsonb),
                    true
                  )
            WHERE tenant_id = $1 AND scan_id = $2`,
          [tenantId, payload.scan_id, noticeVersionId, noticeSummary]
        );
      } else if (payload.scan_id) {
        await db.query(
          `UPDATE scans
              SET findings = jsonb_set(findings::jsonb, '{notice}', $3::jsonb, true)
            WHERE id = $1 AND project_id = $2`,
          [payload.scan_id, project.id, noticeSummary]
        );
      }

      await recordAuditEvent(db, {
        tenantId,
        projectId: project.id,
        scanId: payload.scan_id ?? null,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'notice.locked',
        payload: {
          template: payload.template,
          component_count: approved.length,
          signature_hash: signatureHash,
          notice_version_id: noticeVersionId,
          feed_version: feedVersion,
          signoff: {
            signer_name: payload.signoff.signer_name,
            signer_email: payload.signoff.signer_email ?? null,
            payload: signaturePayload
          }
        }
      });
    }

    const outcome = payload.finalize ? 'finalized' : 'preview';
    endNoticeTimer({ outcome });

    return reply.status(200).send({
      data: {
        document,
        template: payload.template,
        components: approved,
        finalized: Boolean(payload.finalize),
        version_id: noticeVersionId
      }
    });
  });

  app.get('/v1/me/usage', async (request, reply) => {
    const parsed = usageMetricsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const tenantId = authContext.tenantId;
    const days = parsed.data.days;

    const now = new Date();
    const endDayStart = startOfUtcDay(now);
    const windowStart = addUtcDays(endDayStart, -(days - 1));
    const windowEnd = addUtcDays(endDayStart, 1);

    const result = await db.query<UsageMetricRow>(
      `SELECT period_start, period_end, metrics
         FROM usage_metrics
         WHERE tenant_id = $1
           AND period_start >= $2
           AND period_start < $3
         ORDER BY period_start ASC`,
      [tenantId, windowStart.toISOString(), windowEnd.toISOString()]
    );

    const usageByDay = new Map<string, {
      period_start: string;
      period_end: string;
      metrics: NormalizedUsageMetrics;
    }>();
    const metricKeys = new Set<string>(
      DEFAULT_USAGE_METRIC_KEYS.filter((key) => isSafeUsageMetricKey(key))
    );

    for (const row of result.rows) {
      const metricsSource = isRecord(row.metrics) ? row.metrics : {};
      const metrics = normalizeUsageMetrics(metricsSource);
      const periodStartIso = toIsoString(row.period_start);
      const periodEndIso = toIsoString(row.period_end);
      const dayKey = periodStartIso.slice(0, 10);

      for (const key of Object.keys(metrics)) {
        if (!isSafeUsageMetricKey(key)) {
          continue;
        }
        metricKeys.add(key);
      }

      usageByDay.set(dayKey, {
        period_start: periodStartIso,
        period_end: periodEndIso,
        metrics
      });
    }

    const periods: Array<{
      period_start: string;
      period_end: string;
      metrics: NormalizedUsageMetrics;
    }> = [];

    for (let offset = 0; offset < days; offset += 1) {
      const dayStart = addUtcDays(windowStart, offset);
      const nextDay = addUtcDays(dayStart, 1);
      const dayKey = dayStart.toISOString().slice(0, 10);
      const existing = usageByDay.get(dayKey);

      if (existing) {
        periods.push({
          period_start: existing.period_start,
          period_end: existing.period_end,
          metrics: ensureUsageMetricKeys(existing.metrics, metricKeys)
        });
        continue;
      }

      periods.push({
        period_start: dayStart.toISOString(),
        period_end: nextDay.toISOString(),
        metrics: createEmptyUsageMetrics(metricKeys)
      });
    }

    const totals = accumulateUsageTotals(periods.map((entry) => entry.metrics));

    return reply.send({
      data: {
        tenant_id: tenantId,
        totals,
        periods
      }
    });
  });

  app.get('/v1/projects', async (request, reply) => {
    const parsed = listProjectsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;
    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;

    const result = await db.query<ProjectRow>(
      `SELECT id, tenant_id, name, description, repo_url, oci_ref, metadata, created_at, updated_at
         FROM projects
         WHERE tenant_id = $1
         ORDER BY name ASC, id ASC
         LIMIT $2 OFFSET $3`,
      [tenantId, pageSize, offset]
    );

    return reply.send({
      data: result.rows,
      pagination: {
        page,
        page_size: pageSize,
        count: result.rows.length
      }
    });
  });

  app.get('/v1/projects/:id', async (request, reply) => {
    const paramsParsed = getProjectParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid project identifier.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const queryParsed = getProjectQuerySchema.safeParse(request.query);

    if (!queryParsed.success) {
      const message = queryParsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const { id } = paramsParsed.data;
    const requestedTenantId = queryParsed.data.tenant_id;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    if (requestedTenantId && requestedTenantId !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const result = await db.query<ProjectRow>(
      `SELECT id, tenant_id, name, description, repo_url, oci_ref, metadata, created_at, updated_at
         FROM projects
         WHERE id = $1 AND tenant_id = $2
         LIMIT 1`,
      [id, authContext.tenantId]
    );

    const project = result.rows[0];

    if (!project) {
      return sendError(reply, request, 404, 'not_found', 'Project not found.');
    }

    return reply.send({ data: project });
  });

  app.post('/v1/policies', async (request, reply) => {
    const parsed = createPolicySchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;
    const policyId = generateId();

    try {
      const result = await db.query<PolicyRow>(
        `INSERT INTO policies (id, tenant_id, name, description, rules)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, tenant_id, name, description, rules, created_at, updated_at`,
        [policyId, tenantId, payload.name, payload.description ?? null, payload.rules]
      );

      const policy = result.rows[0];

      if (!policy) {
        return sendError(reply, request, 500, 'internal_error', 'Failed to create policy record.');
      }

      return reply.status(201).send({ data: normalizePolicyRow(policy) });
    } catch (error: unknown) {
      const dbError = error as DatabaseError;

      if (dbError.code === '23505') {
        return sendError(reply, request, 409, 'conflict', 'A policy with that name already exists.');
      }

      throw error;
    }
  });

  app.get('/v1/policies/:id', async (request, reply) => {
    const paramsParsed = getPolicyParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid policy identifier.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const result = await db.query<PolicyRow>(
      `SELECT id, tenant_id, name, description, rules, created_at, updated_at
         FROM policies
         WHERE id = $1 AND tenant_id = $2
         LIMIT 1`,
      [paramsParsed.data.id, authContext.tenantId]
    );

    const policy = result.rows[0];

    if (!policy) {
      return sendError(reply, request, 404, 'not_found', 'Policy not found.');
    }

    return reply.send({ data: normalizePolicyRow(policy) });
  });

  function serializeWebhook(
    row: (WebhookRow & Partial<WebhookDeliveryMetadata>) | (WebhookRow & { delivery?: WebhookDeliveryMetadata })
  ) {
    const hasSecret = typeof row.secret_last_four === 'string' && row.secret_last_four.length > 0;
    const failureCountRaw =
      'failure_count' in row && row.failure_count !== undefined && row.failure_count !== null
        ? Number(row.failure_count)
        : 0;

    const failureCount = Number.isFinite(failureCountRaw) ? Math.max(0, Math.trunc(failureCountRaw)) : 0;
    const deliveryMeta: WebhookDeliveryMetadata = {
      last_success_at:
        'last_success_at' in row
          ? (row.last_success_at as Date | string | null)
          : (row as { delivery?: WebhookDeliveryMetadata }).delivery?.last_success_at ?? null,
      last_failure_at:
        'last_failure_at' in row
          ? (row.last_failure_at as Date | string | null)
          : (row as { delivery?: WebhookDeliveryMetadata }).delivery?.last_failure_at ?? null,
      failure_count: failureCount
    };

    const secretSummary = hasSecret
      ? { has_secret: true, last_four: row.secret_last_four, masked: `••••${row.secret_last_four}` }
      : { has_secret: false, last_four: null, masked: null };

    return {
      id: row.id,
      tenant_id: row.tenant_id,
      url: row.url,
      events: Array.isArray(row.events) ? row.events : [],
      created_at: row.created_at,
      updated_at: row.updated_at,
      secret: secretSummary,
      delivery: {
        last_success_at: deliveryMeta.last_success_at ?? null,
        last_failure_at: deliveryMeta.last_failure_at ?? null,
        failure_count: deliveryMeta.failure_count ?? 0
      }
    } satisfies {
      id: string;
      tenant_id: string;
      url: string;
      events: string[];
      created_at: Date | string;
      updated_at: Date | string;
      secret: { has_secret: boolean; last_four: string | null; masked: string | null };
      delivery: WebhookDeliveryMetadata;
    };
  }

  app.get('/v1/webhooks', async (request, reply) => {
    const parsed = listWebhooksQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    if (query.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;
    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;
    const values: unknown[] = [tenantId];
    let eventClause = '';

    if (query.event) {
      values.push(query.event);
      eventClause = ` AND $${values.length} = ANY(events)`;
    }

    values.push(pageSize);
    const limitParamIndex = values.length;
    values.push(offset);
    const offsetParamIndex = values.length;

    const result = await db.query<WebhookRow>(
      `SELECT id, tenant_id, url, secret_last_four, events, created_at, updated_at
         FROM webhooks
        WHERE tenant_id = $1${eventClause}
        ORDER BY created_at DESC, id DESC
        LIMIT $${limitParamIndex} OFFSET $${offsetParamIndex}`,
      values
    );

    const serialized = result.rows.map((row) =>
      serializeWebhook({ ...row, last_success_at: null, last_failure_at: null, failure_count: 0 })
    );

    await recordAuditEvent(db, {
      tenantId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'webhook.listed',
      payload: {
        page,
        page_size: pageSize,
        event_filter: query.event ?? null,
        result_count: serialized.length
      }
    });

    return reply.send({
      data: serialized,
      pagination: {
        page,
        page_size: pageSize,
        count: serialized.length
      }
    });
  });

  app.post('/v1/webhooks', async (request, reply) => {
    const parsed = createWebhookSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;
    const webhookId = generateId();
    const secretValue = typeof payload.secret === 'string' ? payload.secret.trim() : '';
    const hasSecret = secretValue.length > 0;
    const encryptedSecret = hasSecret ? encryptWebhookSecret(secretValue, webhookSecretKey) : null;

    try {
      const result = await db.query<WebhookRow>(
        `INSERT INTO webhooks (
           id,
           tenant_id,
           url,
           secret_ciphertext,
           secret_iv,
           secret_auth_tag,
           secret_last_four,
           events
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING
           id,
           tenant_id,
           url,
           secret_ciphertext,
           secret_iv,
           secret_auth_tag,
           secret_last_four,
           events,
           created_at,
           updated_at`,
        [
          webhookId,
          tenantId,
          payload.url,
          encryptedSecret?.ciphertext ?? null,
          encryptedSecret?.iv ?? null,
          encryptedSecret?.authTag ?? null,
          encryptedSecret?.lastFour ?? null,
          payload.events
        ]
      );

      const webhook = result.rows[0];

      await recordAuditEvent(db, {
        tenantId,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'webhook.created',
        payload: {
          webhook_id: webhookId,
          url: payload.url,
          events: payload.events,
          has_secret: hasSecret
        }
      });

      return reply.status(201).send({ data: serializeWebhook({ ...webhook, failure_count: 0 }) });
    } catch (error: unknown) {
      const dbError = error as DatabaseError;

      if (dbError.code === '23505') {
        return sendError(reply, request, 409, 'conflict', 'A webhook for that URL already exists.');
      }

      throw error;
    }
  });

  app.post('/v1/artifacts', async (request, reply) => {
    const parsed = createArtifactSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const tenantId = authContext.tenantId;
    const metadata: Record<string, unknown> = payload.metadata ?? {};

    const artifactValidationError = validateArtifactDetails({
      type: payload.type,
      ref: payload.ref,
      metadata: payload.metadata
    });

    if (artifactValidationError) {
      return sendError(reply, request, 400, 'validation_error', artifactValidationError);
    }

    const projectResult = await db.query<{ id: string }>(
      'SELECT id FROM projects WHERE id = $1 AND tenant_id = $2 LIMIT 1',
      [payload.project_id, tenantId]
    );

    if (!projectResult.rows[0]) {
      return sendError(reply, request, 404, 'not_found', 'Owning project not found.');
    }

    const artifactId = generateId();

    const result = await db.query<ArtifactRow>(
      `INSERT INTO artifacts (id, project_id, type, ref, metadata)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, project_id, type, ref, metadata, created_at`,
      [artifactId, payload.project_id, payload.type, payload.ref, metadata]
    );

    const artifact = result.rows[0];

    return reply.status(201).send({ data: artifact });
  });

  app.post('/v1/sboms/import', async (request, reply) => {
    const parsed = importSbomSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = await ensureRoleAccess(request, reply, ['Admin', 'Developer', 'Security']);

    if (!authContext) {
      return;
    }

    if (payload.tenant_id !== authContext.tenantId) {
      return sendError(reply, request, 403, 'forbidden', tenantScopeMessage);
    }

    const tenantId = authContext.tenantId;

    const projectResult = await db.query<ProjectRow>(
      'SELECT id, tenant_id, name, description, repo_url, oci_ref, metadata FROM projects WHERE id = $1 AND tenant_id = $2 LIMIT 1',
      [payload.project_id, tenantId]
    );

    const project = projectResult.rows[0];

    if (!project) {
      return sendError(reply, request, 404, 'not_found', 'Project not found.');
    }

    let artifactId: string | null = payload.artifact_id ?? null;

    if (artifactId) {
      const artifactResult = await db.query<{ id: string }>(
        'SELECT id FROM artifacts WHERE id = $1 AND project_id = $2 LIMIT 1',
        [artifactId, payload.project_id]
      );

      if (!artifactResult.rows[0]) {
        return sendError(reply, request, 404, 'not_found', 'Artifact not found for project.');
      }
    }

    let policyRules: PolicyRules | null = null;

    if (payload.policy_id) {
      const policyResult = await db.query<PolicyRow>(
        'SELECT rules FROM policies WHERE id = $1 AND tenant_id = $2 LIMIT 1',
        [payload.policy_id, tenantId]
      );

      if (!policyResult.rows[0]) {
        return sendError(reply, request, 404, 'not_found', 'Policy not found.');
      }

      policyRules = policyResult.rows[0].rules;
    }

    const sbomByteSize = Buffer.byteLength(JSON.stringify(payload.sbom ?? {}), 'utf8');

    if (sbomByteSize > MAX_IMPORTED_SBOM_BYTES) {
      return sendError(
        reply,
        request,
        413,
        'payload_too_large',
        'SBOM payload exceeds the 5 MiB upload limit.'
      );
    }

    const normalized = normalizeImportedSbom({ format: payload.format, document: payload.sbom });
    const scannerResult = buildScannerResultFromImport(normalized);
    const componentCount = scannerResult.packages.length;
    const sbomId = generateId();
    const scanId = generateId();
    const now = new Date();
    const startedAtIso = now.toISOString();
    const completedAtIso = startedAtIso;

    const evaluation = policyRules
      ? await evaluatePolicyWithOpa({ rules: policyRules, scannerResult })
      : { result: 'pass' as const, reasons: [] as string[], opaDecisions: [] as string[] };

    const policySeverity: 'pass' | 'warn' | 'fail' = evaluation.result === 'fail' ? 'fail' : 'pass';
    const policyReasons = [...evaluation.reasons];

    const findingsSummary = {
      packages: scannerResult.packages.length,
      licenses: scannerResult.licenses.length,
      vulnerabilities: scannerResult.vulnerabilities.length,
      vex: {
        downgraded: 0,
        total: scannerResult.vulnerabilities.length
      },
      policy: { result: policySeverity, reasons: policyReasons },
      duration_ms: 0,
      webhooks: { delivered: 0, failed: 0, failures: [] as Array<Record<string, unknown>> }
    } satisfies Record<string, unknown>;

    const tenantMetadataResult = await db.query<{ metadata: Record<string, unknown> | null }>(
      'SELECT metadata FROM tenants WHERE id = $1 LIMIT 1',
      [tenantId]
    );
    const tenantMetadata = tenantMetadataResult.rows[0]?.metadata ?? {};
    const feedVersionCandidate =
      tenantMetadata && typeof tenantMetadata === 'object'
        ? (tenantMetadata as Record<string, unknown>).active_feed_version
        : null;
    const activeFeedVersion = typeof feedVersionCandidate === 'string' ? feedVersionCandidate : null;

    const packagesByName = new Map<string, string>();

    for (const pkg of scannerResult.packages) {
      packagesByName.set(pkg.name, pkg.purl);
    }

    const scanRow: ScanRow = {
      id: scanId,
      project_id: payload.project_id,
      artifact_id: artifactId,
      policy_id: payload.policy_id ?? null,
      policy_result: policySeverity,
      status: 'succeeded',
      findings: findingsSummary,
      duration_ms: 0,
      started_at: startedAtIso,
      completed_at: completedAtIso,
      created_at: startedAtIso
    };

    const evidencePack = await buildEvidencePack({
      tenantId,
      projectId: payload.project_id,
      scanId,
      feedVersion: activeFeedVersion,
      noticeVersionId: null,
      entries: [
        { path: 'sbom.import.json', data: normalized.bom, mediaType: 'application/json' },
        { path: 'packages.json', data: scannerResult.packages, mediaType: 'application/json' },
        { path: 'licenses.json', data: scannerResult.licenses, mediaType: 'application/json' },
        {
          path: 'policy-evaluation.json',
          data: { result: policySeverity, reasons: policyReasons },
          mediaType: 'application/json'
        },
        { path: 'findings-summary.json', data: findingsSummary, mediaType: 'application/json' },
        { path: 'feed-info.json', data: { active_feed_version: activeFeedVersion }, mediaType: 'application/json' }
      ],
      purgeManifest: null
    });

    try {
      await db.query('BEGIN');

      await db.query(
        `INSERT INTO scans (id, project_id, artifact_id, policy_id, policy_result, status, findings, duration_ms, started_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, 'succeeded', $6, $7, $8, $9)`,
        [
          scanId,
          payload.project_id,
          artifactId,
          payload.policy_id ?? null,
          policySeverity,
          findingsSummary,
          0,
          startedAtIso,
          completedAtIso
        ]
      );

      await db.query(
        `INSERT INTO sboms (id, project_id, artifact_id, scan_id, format, bom, component_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [sbomId, payload.project_id, artifactId, scanId, normalized.format, normalized.bom, componentCount]
      );

      for (const license of scannerResult.licenses) {
        const licenseId = generateId();
        const componentPurl =
          (license.packageName ? packagesByName.get(license.packageName) : undefined) ?? `file:${license.path}`;
        const obligations = deriveLicenseObligations({ spdxId: license.spdxId ?? null });

        await db.query(
          `INSERT INTO licenses (id, sbom_id, component_purl, detected_spdx_id, evidence)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            licenseId,
            sbomId,
            componentPurl,
            license.spdxId ?? null,
            { path: license.path, component: license.packageName ?? null, spdx: license.spdxId ?? null }
          ]
        );

        await db.query(
          `INSERT INTO legal_findings (id, tenant_id, license_id, scan_id, status, obligations, notes)
           VALUES ($1, $2, $3, $4, 'pending', $5, $6)`,
          [generateId(), tenantId, licenseId, scanId, obligations, null]
        );
      }

      await db.query(
        `INSERT INTO evidence_packs (tenant_id, project_id, scan_id, storage_path, manifest, signature, hash_algorithm)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (tenant_id, scan_id) DO UPDATE
           SET storage_path = EXCLUDED.storage_path,
               manifest = EXCLUDED.manifest,
               signature = EXCLUDED.signature,
               hash_algorithm = EXCLUDED.hash_algorithm`,
        [
          tenantId,
          payload.project_id,
          scanId,
          null,
          evidencePack.manifest,
          evidencePack.signature?.value ?? null,
          evidencePack.hashAlgorithm
        ]
      );

      await db.query('COMMIT');
    } catch (error) {
      await db.query('ROLLBACK');
      throw error;
    }

    await recordAuditEvent(db, {
      tenantId,
      projectId: payload.project_id,
      scanId,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'sbom.imported',
      payload: {
        scan_id: scanId,
        project_id: payload.project_id,
        artifact_id: artifactId,
        policy_id: payload.policy_id ?? null,
        format: normalized.format,
        sbom_sha256: hashSbomDocument(normalized.bom)
      }
    });

    return reply.status(201).send({ data: serializeScan(scanRow) });
  });

  app.post('/v1/scans', async (request, reply) => {
    const parsed = createScanSchema.safeParse(request.body);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid request body.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const payload = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const tenantId = authContext.tenantId;

    const projectResult = await db.query<ProjectRow>(
      'SELECT id, tenant_id, name, description, repo_url, oci_ref, metadata FROM projects WHERE id = $1 AND tenant_id = $2 LIMIT 1',
      [payload.project_id, tenantId]
    );

    const project = projectResult.rows[0];

    if (!project) {
      return sendError(reply, request, 404, 'not_found', 'Project not found.');
    }

    if (payload.policy_id) {
      const policyResult = await db.query<{ id: string }>(
        'SELECT id FROM policies WHERE id = $1 AND tenant_id = $2 LIMIT 1',
        [payload.policy_id, tenantId]
      );

      if (!policyResult.rows[0]) {
        return sendError(reply, request, 404, 'not_found', 'Policy not found.');
      }
    }

    if (payload.artifact) {
      const validationError = validateArtifactDetails(payload.artifact);

      if (validationError) {
        return sendError(reply, request, 400, 'validation_error', validationError);
      }
    }

    let artifactId: string | null = payload.artifact_id ?? null;
    let artifactToCreate: ArtifactDetails | null = null;

    if (payload.artifact_id) {
      const artifactResult = await db.query<{ id: string }>(
        'SELECT id FROM artifacts WHERE id = $1 AND project_id = $2 LIMIT 1',
        [payload.artifact_id, payload.project_id]
      );

      if (!artifactResult.rows[0]) {
        return sendError(reply, request, 404, 'not_found', 'Artifact not found for project.');
      }
    }

    if (!artifactId) {
      if (payload.artifact) {
        artifactToCreate = payload.artifact;
      } else {
        artifactToCreate = buildAutoArtifact(project);

        if (!artifactToCreate) {
          return sendError(
            reply,
            request,
            400,
            'validation_error',
            'Project does not define repo_url or oci_ref for artifact creation.'
          );
        }
      }
    }

    if (artifactToCreate) {
      const validationError = validateArtifactDetails(artifactToCreate);

      if (validationError) {
        return sendError(reply, request, 400, 'validation_error', validationError);
      }
    }

    const rawIdempotencyKey = extractIdempotencyKey(request.headers[IDEMPOTENCY_KEY_HEADER]);

    if (!rawIdempotencyKey) {
      return sendError(
        reply,
        request,
        400,
        'validation_error',
        'Idempotency-Key header is required to submit scans.'
      );
    }

    const idempotencyKey = rawIdempotencyKey.trim();

    if (
      idempotencyKey.length === 0 ||
      idempotencyKey.length > IDEMPOTENCY_KEY_MAX_LENGTH ||
      !IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)
    ) {
      return sendError(
        reply,
        request,
        400,
        'validation_error',
        'Idempotency-Key must be 1-128 URL-safe characters.'
      );
    }

    const keyHash = hashIdempotencyKey(idempotencyKey, apiKeySalt);
    const scanRequestId = randomUUID();

    const claimResult = await db.query<{ id: string }>(
      `INSERT INTO scan_requests (id, tenant_id, key_hash)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, key_hash) DO NOTHING
         RETURNING id`,
      [scanRequestId, tenantId, keyHash]
    );

    if (!claimResult.rows[0]) {
      const existingScan = await fetchExistingScanForKey(db, tenantId, keyHash);

      if (!existingScan) {
        return sendError(
          reply,
          request,
          409,
          'conflict',
          'A scan request with this Idempotency-Key is still processing. Retry shortly.'
        );
      }

      return reply.status(200).send({ data: serializeScan(existingScan) });
    }

    let scanId: string | null = null;
    let cleanupClaim = true;

    try {
      if (artifactToCreate) {
        artifactId = artifactId ?? generateId();
        const metadata: Record<string, unknown> = artifactToCreate.metadata ?? {};

        await db.query(
          `INSERT INTO artifacts (id, project_id, type, ref, metadata)
             VALUES ($1, $2, $3, $4, $5)`,
          [artifactId, payload.project_id, artifactToCreate.type, artifactToCreate.ref, metadata]
        );
      }

      scanId = generateId();
      const initialPolicyResult: 'pass' | 'warn' | 'fail' | null = null;

      const result = await db.query<ScanRow>(
        `INSERT INTO scans (id, project_id, artifact_id, policy_id, policy_result, status, findings)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, project_id, artifact_id, policy_id, policy_result, status, findings, duration_ms, started_at, completed_at, created_at`,
        [scanId, payload.project_id, artifactId, payload.policy_id ?? null, initialPolicyResult, 'queued', {}]
      );

      const scan = serializeScan(result.rows[0]);

      await db.query('UPDATE scan_requests SET scan_id = $1 WHERE id = $2', [scanId, scanRequestId]);

      await queue.add('scan', {
        scan_id: scanId,
        project_id: payload.project_id,
        artifact_id: artifactId,
        policy_id: payload.policy_id ?? null
      });

      await recordAuditEvent(db, {
        tenantId,
        projectId: payload.project_id,
        scanId,
        actorType: 'api_key',
        actorIdentifier: authContext.apiKeyId,
        eventType: 'scan.submitted',
        payload: {
          scan_id: scanId,
          project_id: payload.project_id,
          artifact_id: artifactId,
          policy_id: payload.policy_id ?? null,
          idempotency_key_hash: keyHash
        }
      });

      cleanupClaim = false;

      return reply.status(201).send({ data: scan });
    } catch (error) {
      if (scanId) {
        try {
          await db.query('DELETE FROM scans WHERE id = $1', [scanId]);
        } catch (cleanupError) {
          request.log.error({ err: cleanupError, scanId }, 'Failed to roll back scan record after enqueue error.');
        }
      }

      if (cleanupClaim) {
        try {
          await db.query('DELETE FROM scan_requests WHERE id = $1', [scanRequestId]);
        } catch (cleanupError) {
          request.log.error({ err: cleanupError, scanRequestId }, 'Failed to roll back scan request claim.');
        }
      }

      throw error;
    }
  });

  app.get('/v1/scans', async (request, reply) => {
    const parsed = listScansQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const filters: string[] = ['p.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    if (query.project_id) {
      filters.push(`s.project_id = $${values.length + 1}`);
      values.push(query.project_id);
    }

    if (query.status) {
      filters.push(`s.status = $${values.length + 1}`);
      values.push(query.status);
    }

    if (query.policy_result) {
      filters.push(`s.policy_result = $${values.length + 1}`);
      values.push(query.policy_result);
    }

    if (query.created_from) {
      filters.push(`s.created_at >= $${values.length + 1}`);
      values.push(query.created_from.toISOString());
    }

    if (query.created_to) {
      filters.push(`s.created_at <= $${values.length + 1}`);
      values.push(query.created_to.toISOString());
    }

    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;

    const limitIndex = values.length + 1;
    const offsetIndex = values.length + 2;

    const paginationValues = [...values, pageSize, offset];

    const whereClause = `WHERE ${filters.join(' AND ')}`;

    const result = await db.query<ScanRow & { total_count: string | number }>(
      `SELECT s.id,
              s.project_id,
              s.artifact_id,
              s.policy_id,
              s.policy_result,
              s.status,
              s.findings,
              s.duration_ms,
              s.started_at,
              s.completed_at,
              s.created_at,
              COUNT(*) OVER() AS total_count
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
         ${whereClause}
         ORDER BY s.created_at DESC, s.id DESC
         LIMIT $${limitIndex} OFFSET $${offsetIndex}`,
      paginationValues
    );

    let total = result.rows[0]?.total_count ?? 0;

    if (result.rows.length === 0) {
      const countResult = await db.query<{ total: string | number }>(
        `SELECT COUNT(*) AS total
           FROM scans s
           INNER JOIN projects p ON p.id = s.project_id
           ${whereClause}`,
        values
      );

      total = countResult.rows[0]?.total ?? 0;
    }

    return reply.send({
      data: result.rows.map(({ total_count, ...row }) => serializeScan(row)),
      pagination: {
        page,
        page_size: pageSize,
        count: result.rows.length,
        total: typeof total === 'string' ? Number(total) : total
      }
    });
  });

  app.get('/v1/scans/:id', async (request, reply) => {
    const paramsParsed = getScanParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid scan identifier.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const result = await db.query<ScanRow>(
      `SELECT s.id, s.project_id, s.artifact_id, s.policy_id, s.policy_result, s.status, s.findings, s.duration_ms, s.started_at, s.completed_at, s.created_at
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
         WHERE s.id = $1 AND p.tenant_id = $2
         LIMIT 1`,
      [paramsParsed.data.id, authContext.tenantId]
    );

    const scan = result.rows[0];

    if (!scan) {
      return sendError(reply, request, 404, 'not_found', 'Scan not found.');
    }

    return reply.send({ data: serializeScan(scan) });
  });

  app.get('/v1/sboms/:scan_id', async (request, reply) => {
    const paramsParsed = getSbomParamsSchema.safeParse(request.params);

    if (!paramsParsed.success) {
      const message = paramsParsed.error.errors[0]?.message ?? 'Invalid scan identifier.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const result = await db.query<SbomRow>(
      `SELECT sb.format, sb.bom
         FROM sboms sb
         INNER JOIN scans s ON s.id = sb.scan_id
         INNER JOIN projects p ON p.id = s.project_id
         WHERE sb.scan_id = $1 AND p.tenant_id = $2
         ORDER BY sb.created_at DESC, sb.id DESC
         LIMIT 1`,
      [paramsParsed.data.scan_id, authContext.tenantId]
    );

    const sbom = result.rows[0];

    if (!sbom) {
      return sendError(reply, request, 404, 'not_found', 'SBOM not found.');
    }

    void reply.header('content-type', 'application/vnd.cyclonedx+json');
    return reply.send({ ...sbom.bom });
  });

  app.get('/v1/licenses', async (request, reply) => {
    const parsed = listLicensesQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const filters: string[] = ['p.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    if (query.scan_id) {
      filters.push(`sc.id = $${values.length + 1}`);
      values.push(query.scan_id);
    }

    if (query.spdx_id) {
      filters.push(`l.detected_spdx_id = $${values.length + 1}`);
      values.push(query.spdx_id);
    }

    if (query.component_purl) {
      filters.push(`l.component_purl = $${values.length + 1}`);
      values.push(query.component_purl);
    }

    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;

    const limitIndex = values.length + 1;
    const offsetIndex = values.length + 2;
    values.push(pageSize, offset);

    const whereClause = `WHERE ${filters.join(' AND ')}`;

    const result = await db.query<LicenseRow>(
      `SELECT l.id, l.sbom_id, sc.id AS scan_id, l.component_purl, l.detected_spdx_id, l.evidence, l.created_at
         FROM licenses l
         JOIN sboms sb ON sb.id = l.sbom_id
         JOIN scans sc ON sc.id = sb.scan_id
         JOIN projects p ON p.id = sc.project_id
         ${whereClause}
         ORDER BY l.created_at DESC, l.id DESC
         LIMIT $${limitIndex} OFFSET $${offsetIndex}`,
      values
    );

    return reply.send({
      data: result.rows.map(serializeLicense),
      pagination: {
        page,
        page_size: pageSize,
        count: result.rows.length
      }
    });
  });

  app.get('/v1/vulns', async (request, reply) => {
    const parsed = listVulnsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const filters: string[] = ['p.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    if (query.scan_id) {
      filters.push(`v.scan_id = $${values.length + 1}`);
      values.push(query.scan_id);
    }

    if (query.severity) {
      filters.push(`v.severity = $${values.length + 1}`);
      values.push(query.severity);
    }

    if (query.component_purl) {
      filters.push(`v.component_purl = $${values.length + 1}`);
      values.push(query.component_purl);
    }

    if (typeof query.cvss_min === 'number') {
      filters.push(`v.cvss >= $${values.length + 1}`);
      values.push(query.cvss_min);
    }

    const page = query.page;
    const pageSize = query.page_size;
    const offset = (page - 1) * pageSize;

    const limitIndex = values.length + 1;
    const offsetIndex = values.length + 2;
    values.push(pageSize, offset);

    const whereClause = `WHERE ${filters.join(' AND ')}`;

    const result = await db.query<VulnRow>(
      `SELECT v.id, v.scan_id, v.component_purl, v.source, v.cve_id, v.severity, v.cvss, v.summary, v.fixed_version, v.detected_at
         FROM vulns v
         INNER JOIN scans sc ON sc.id = v.scan_id
         INNER JOIN projects p ON p.id = sc.project_id
         ${whereClause}
         ORDER BY v.detected_at DESC, v.id DESC
         LIMIT $${limitIndex} OFFSET $${offsetIndex}`,
      values
    );

    return reply.send({
      data: result.rows.map(serializeVulnerability),
      pagination: {
        page,
        page_size: pageSize,
        count: result.rows.length
      }
    });
  });

  app.get('/v1/audit/events', async (request, reply) => {
    const authContext = await ensureRoleAccess(request, reply, ['Admin', 'Auditor']);

    if (!authContext) {
      return;
    }

    const parsed = auditEventsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const query = parsed.data;
    const limit = query.limit ?? 50;
    const format = query.format ?? 'json';
    const decodedCursor = query.cursor ? decodeAuditCursor(query.cursor) : null;

    if (query.cursor && !decodedCursor) {
      return sendError(reply, request, 400, 'validation_error', 'Invalid cursor value.');
    }

    const filters: string[] = ['e.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    if (query.project_id) {
      filters.push(`e.project_id = $${values.length + 1}`);
      values.push(query.project_id);
    }

    if (query.event_type) {
      filters.push(`e.event_type = $${values.length + 1}`);
      values.push(query.event_type);
    }

    if (query.actor) {
      const actorIndex = values.length + 1;
      filters.push(`(e.actor_identifier = $${actorIndex} OR e.actor_type = $${actorIndex})`);
      values.push(query.actor);
    }

    if (query.from) {
      filters.push(`e.created_at >= $${values.length + 1}`);
      values.push(query.from.toISOString());
    }

    if (query.to) {
      filters.push(`e.created_at <= $${values.length + 1}`);
      values.push(query.to.toISOString());
    }

    if (decodedCursor) {
      const timestampIndex = values.length + 1;
      const idIndex = values.length + 2;
      filters.push(`(e.created_at, e.id) < ($${timestampIndex}::timestamptz, $${idIndex}::uuid)`);
      values.push(toIsoTimestamp(decodedCursor.created_at), decodedCursor.id);
    }

    const whereClause = `WHERE ${filters.join(' AND ')}`;
    const limitIndex = values.length + 1;
    values.push(limit + 1);

    const result = await db.query<AuditEventRow>(
      `SELECT
         e.id,
         e.tenant_id,
         e.project_id,
         e.scan_id,
         e.actor_type,
         e.actor_identifier,
         e.event_type,
         e.event_payload,
         e.event_hash,
         e.created_at
       FROM audit_log_events e
       ${whereClause}
       ORDER BY e.created_at DESC, e.id DESC
       LIMIT $${limitIndex}`,
      values
    );

    const rows = result.rows ?? [];
    let nextCursor: string | null = null;

    if (rows.length > limit) {
      const cursorSource = rows[limit];
      nextCursor = encodeAuditCursor({
        createdAt: toIsoTimestamp(cursorSource.created_at),
        id: cursorSource.id
      });
    }

    const visibleRows = rows.slice(0, limit).map((row) => ({
      id: row.id,
      tenant_id: row.tenant_id,
      project_id: row.project_id ?? null,
      scan_id: row.scan_id ?? null,
      actor_type: row.actor_type,
      actor_identifier: row.actor_identifier ?? null,
      event_type: row.event_type,
      event_payload: row.event_payload ?? {},
      event_hash: row.event_hash,
      created_at: toIsoTimestamp(row.created_at)
    }));

    reply.header('cache-control', 'no-store');

    if (format === 'jsonl') {
      if (nextCursor) {
        reply.header('x-next-cursor', nextCursor);
      }

      const lines = visibleRows.map((row) => JSON.stringify(row));
      reply.type('application/x-ndjson; charset=utf-8');
      return reply.send(lines.length > 0 ? `${lines.join('\n')}\n` : '');
    }

    return reply.send({
      data: visibleRows,
      pagination: {
        limit,
        next_cursor: nextCursor
      }
    });
  });

  app.get('/v1/reports/summary', async (request, reply) => {
    const parsed = reportsSummaryQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const query = parsed.data;
    const filters: string[] = ['p.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    if (query.project_id) {
      filters.push(`s.project_id = $${values.length + 1}`);
      values.push(query.project_id);
    }

    if (query.from) {
      filters.push(`s.created_at >= $${values.length + 1}`);
      values.push(query.from.toISOString());
    }

    if (query.to) {
      filters.push(`s.created_at <= $${values.length + 1}`);
      values.push(query.to.toISOString());
    }

    const whereClause = `WHERE ${filters.join(' AND ')}`;

    const summaryResult = await db.query<{
      total_scans: string | number | null;
      policy_pass: string | number | null;
      policy_warn: string | number | null;
      policy_fail: string | number | null;
      license_violations: string | number | null;
      average_duration_ms: string | number | null;
      vuln_critical: string | number | null;
      vuln_high: string | number | null;
      vuln_medium: string | number | null;
      vuln_low: string | number | null;
      vex_total: string | number | null;
      vex_downgraded: string | number | null;
    }>(
      `WITH filtered_scans AS (
         SELECT
           s.id,
           s.policy_result,
           s.duration_ms,
           COALESCE(s.findings::jsonb, '{}'::jsonb) AS findings
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
         ${whereClause}
       ),
       enriched AS (
         SELECT
           id,
           CASE
             WHEN LOWER(COALESCE(policy_result, '')) IN ('allowed', 'pass') THEN 'pass'
             WHEN LOWER(COALESCE(policy_result, '')) IN ('warn', 'warning', 'pending') THEN 'warn'
             WHEN LOWER(COALESCE(policy_result, '')) IN ('fail', 'failed', 'denied') THEN 'fail'
             ELSE 'pass'
           END AS normalized_policy,
           CASE
             WHEN duration_ms IS NULL THEN NULL
             WHEN (duration_ms::text) ~ '^[0-9]+(\\.[0-9]+)?$' THEN (duration_ms::text)::numeric
             ELSE NULL
           END AS duration_ms_numeric,
           CASE
             WHEN jsonb_typeof(findings -> 'license_violations') = 'number' THEN (findings ->> 'license_violations')::numeric
             WHEN jsonb_typeof(findings -> 'license_violations') = 'array' THEN jsonb_array_length(findings -> 'license_violations')
             WHEN jsonb_typeof(findings -> 'licenses') = 'object'
                  AND jsonb_typeof(findings -> 'licenses' -> 'violations') = 'number'
               THEN (findings -> 'licenses' ->> 'violations')::numeric
             WHEN jsonb_typeof(findings -> 'licenses') = 'object'
                  AND jsonb_typeof(findings -> 'licenses' -> 'violations') = 'array'
               THEN jsonb_array_length(findings -> 'licenses' -> 'violations')
             ELSE 0
           END AS license_violation_count,
           CASE
             WHEN jsonb_typeof(findings -> 'vex') = 'object'
                  AND jsonb_typeof(findings -> 'vex' -> 'downgraded') = 'number'
               THEN (findings -> 'vex' ->> 'downgraded')::numeric
             ELSE 0
           END AS vex_downgraded_count,
           CASE
             WHEN jsonb_typeof(findings -> 'vex') = 'object'
                  AND jsonb_typeof(findings -> 'vex' -> 'total') = 'number'
               THEN (findings -> 'vex' ->> 'total')::numeric
             WHEN jsonb_typeof(findings -> 'vulnerabilities') = 'array'
               THEN jsonb_array_length(findings -> 'vulnerabilities')
             ELSE 0
           END AS vex_total_count
         FROM filtered_scans
       ),
       summary AS (
         SELECT
           COUNT(*) AS total_scans,
           COUNT(*) FILTER (WHERE normalized_policy = 'pass') AS policy_pass,
           COUNT(*) FILTER (WHERE normalized_policy = 'warn') AS policy_warn,
           COUNT(*) FILTER (WHERE normalized_policy = 'fail') AS policy_fail,
           COALESCE(SUM(license_violation_count), 0) AS license_violations,
           AVG(duration_ms_numeric) AS average_duration_ms,
           COALESCE(SUM(vex_total_count), 0) AS vex_total,
           COALESCE(SUM(vex_downgraded_count), 0) AS vex_downgraded
         FROM enriched
       ),
       vuln_counts AS (
         SELECT
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'critical' THEN 1 ELSE 0 END), 0) AS critical,
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'high' THEN 1 ELSE 0 END), 0) AS high,
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'medium' THEN 1 ELSE 0 END), 0) AS medium,
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'low' THEN 1 ELSE 0 END), 0) AS low
         FROM vulns v
         INNER JOIN scans s ON s.id = v.scan_id
         INNER JOIN projects p ON p.id = s.project_id
         ${whereClause}
       )
       SELECT
         summary.total_scans,
         summary.policy_pass,
         summary.policy_warn,
         summary.policy_fail,
         summary.license_violations,
         summary.average_duration_ms,
         summary.vex_total,
         summary.vex_downgraded,
         vuln_counts.critical AS vuln_critical,
         vuln_counts.high AS vuln_high,
         vuln_counts.medium AS vuln_medium,
         vuln_counts.low AS vuln_low
       FROM summary
       CROSS JOIN vuln_counts`,
      values
    );

    const summary = normalizeReportsSummaryRow(summaryResult.rows[0] ?? null);

    return reply.send({
      data: summary
    });
  });

  app.get('/v1/reports/export', async (request, reply) => {
    const parsed = reportsSummaryQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const query = parsed.data;
    const filters: string[] = ['p.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    if (query.project_id) {
      filters.push(`s.project_id = $${values.length + 1}`);
      values.push(query.project_id);
    }

    if (query.from) {
      filters.push(`s.created_at >= $${values.length + 1}`);
      values.push(query.from.toISOString());
    }

    if (query.to) {
      filters.push(`s.created_at <= $${values.length + 1}`);
      values.push(query.to.toISOString());
    }

    const whereClause = `WHERE ${filters.join(' AND ')}`;

    const summaryResult = await db.query<ReportsSummaryAggregate>(
      `WITH filtered_scans AS (
         SELECT
           s.id,
           s.policy_result,
           s.duration_ms,
           COALESCE(s.findings::jsonb, '{}'::jsonb) AS findings
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
         ${whereClause}
       ),
       enriched AS (
         SELECT
           id,
           CASE
             WHEN LOWER(COALESCE(policy_result, '')) IN ('allowed', 'pass') THEN 'pass'
             WHEN LOWER(COALESCE(policy_result, '')) IN ('warn', 'warning', 'pending') THEN 'warn'
             WHEN LOWER(COALESCE(policy_result, '')) IN ('fail', 'failed', 'denied') THEN 'fail'
             ELSE 'pass'
           END AS normalized_policy,
           CASE
             WHEN duration_ms IS NULL THEN NULL
             WHEN (duration_ms::text) ~ '^[0-9]+(\\.[0-9]+)?$' THEN (duration_ms::text)::numeric
             ELSE NULL
           END AS duration_ms_numeric,
           CASE
             WHEN jsonb_typeof(findings -> 'license_violations') = 'number' THEN (findings ->> 'license_violations')::numeric
             WHEN jsonb_typeof(findings -> 'license_violations') = 'array' THEN jsonb_array_length(findings -> 'license_violations')
             WHEN jsonb_typeof(findings -> 'licenses') = 'object'
                  AND jsonb_typeof(findings -> 'licenses' -> 'violations') = 'number'
               THEN (findings -> 'licenses' ->> 'violations')::numeric
             WHEN jsonb_typeof(findings -> 'licenses') = 'object'
                  AND jsonb_typeof(findings -> 'licenses' -> 'violations') = 'array'
               THEN jsonb_array_length(findings -> 'licenses' -> 'violations')
             ELSE 0
           END AS license_violation_count,
           CASE
             WHEN jsonb_typeof(findings -> 'vex') = 'object'
                  AND jsonb_typeof(findings -> 'vex' -> 'downgraded') = 'number'
               THEN (findings -> 'vex' ->> 'downgraded')::numeric
             ELSE 0
           END AS vex_downgraded_count,
           CASE
             WHEN jsonb_typeof(findings -> 'vex') = 'object'
                  AND jsonb_typeof(findings -> 'vex' -> 'total') = 'number'
               THEN (findings -> 'vex' ->> 'total')::numeric
             WHEN jsonb_typeof(findings -> 'vulnerabilities') = 'array'
               THEN jsonb_array_length(findings -> 'vulnerabilities')
             ELSE 0
           END AS vex_total_count
         FROM filtered_scans
       ),
       summary AS (
         SELECT
           COUNT(*) AS total_scans,
           COUNT(*) FILTER (WHERE normalized_policy = 'pass') AS policy_pass,
           COUNT(*) FILTER (WHERE normalized_policy = 'warn') AS policy_warn,
           COUNT(*) FILTER (WHERE normalized_policy = 'fail') AS policy_fail,
           COALESCE(SUM(license_violation_count), 0) AS license_violations,
           AVG(duration_ms_numeric) AS average_duration_ms,
           COALESCE(SUM(vex_total_count), 0) AS vex_total,
           COALESCE(SUM(vex_downgraded_count), 0) AS vex_downgraded
         FROM enriched
       ),
       vuln_counts AS (
         SELECT
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'critical' THEN 1 ELSE 0 END), 0) AS vuln_critical,
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'high' THEN 1 ELSE 0 END), 0) AS vuln_high,
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'medium' THEN 1 ELSE 0 END), 0) AS vuln_medium,
           COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'low' THEN 1 ELSE 0 END), 0) AS vuln_low
         FROM vulns v
         INNER JOIN scans s ON s.id = v.scan_id
         INNER JOIN projects p ON p.id = s.project_id
         ${whereClause}
       )
       SELECT
         summary.total_scans,
         summary.policy_pass,
         summary.policy_warn,
         summary.policy_fail,
         summary.license_violations,
         summary.average_duration_ms,
         summary.vex_total,
         summary.vex_downgraded,
         vuln_counts.vuln_critical,
         vuln_counts.vuln_high,
         vuln_counts.vuln_medium,
         vuln_counts.vuln_low
       FROM summary
       CROSS JOIN vuln_counts`,
      values
    );

    const summary = normalizeReportsSummaryRow(summaryResult.rows[0] ?? null);
    const headers = [
      'total_scans',
      'policy_pass',
      'policy_warn',
      'policy_fail',
      'license_violations',
      'average_duration_ms',
      'vuln_critical',
      'vuln_high',
      'vuln_medium',
      'vuln_low',
      'vex_total',
      'vex_downgraded',
      'vex_ratio'
    ];
    const row = [
      summary.total_scans,
      summary.policy.pass,
      summary.policy.warn,
      summary.policy.fail,
      summary.license_violations,
      summary.average_duration_ms ?? '',
      summary.vulnerabilities.critical,
      summary.vulnerabilities.high,
      summary.vulnerabilities.medium,
      summary.vulnerabilities.low,
      summary.vex_noise_reduction.total,
      summary.vex_noise_reduction.downgraded,
      summary.vex_noise_reduction.ratio
    ];

    const csvContent = `${headers.map(csvEscape).join(',')}\n${row.map(csvEscape).join(',')}\n`;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const projectSuffix = query.project_id ? `-project-${query.project_id}` : '';
    const fileName = `atlas-reports-${authContext.tenantId}${projectSuffix}-${timestamp}.csv`;

    await recordAuditEvent(db, {
      tenantId: authContext.tenantId,
      projectId: query.project_id ?? null,
      actorType: 'api_key',
      actorIdentifier: authContext.apiKeyId,
      eventType: 'reports.exported',
      payload: {
        project_id: query.project_id ?? null,
        from: query.from ? query.from.toISOString() : null,
        to: query.to ? query.to.toISOString() : null,
        file_name: fileName,
        columns: headers
      }
    });

    reply.header('content-type', 'text/csv; charset=utf-8');
    reply.header('content-disposition', `attachment; filename="${fileName}"`);
    reply.header('cache-control', 'no-store');

    return reply.send(csvContent);
  });

  app.get('/v1/changes', async (request, reply) => {
    const parsed = changesQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      const message = parsed.error.errors[0]?.message ?? 'Invalid query parameters.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const authContext = request.authContext;

    if (!authContext) {
      return sendError(reply, request, 500, 'internal_error', 'Authentication context missing.');
    }

    const query = parsed.data;
    const filters: string[] = ['p.tenant_id = $1'];
    const values: unknown[] = [authContext.tenantId];

    filters.push(`COALESCE(s.completed_at, s.created_at) >= $${values.length + 1}`);
    values.push(query.since.toISOString());

    if (query.type === 'scan.completed') {
      filters.push("s.status = 'succeeded'");
    } else if (query.type === 'scan.failed') {
      filters.push("s.status = 'failed'");
    } else {
      filters.push("s.status IN ('succeeded', 'failed')");
    }

    const whereClause = `WHERE ${filters.join(' AND ')}`;

    const result = await db.query<{
      id: string;
      project_id: string;
      project_name: string;
      status: string;
      policy_result: string | null;
      completed_at: Date | string | null;
      created_at: Date | string;
    }>(
      `SELECT s.id, s.project_id, p.name AS project_name, s.status, s.policy_result, s.completed_at, s.created_at
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
         ${whereClause}
         ORDER BY COALESCE(s.completed_at, s.created_at) DESC, s.id DESC
         LIMIT 200`,
      values
    );

    const events = result.rows.map((row) => {
      const occurredAtValue = row.completed_at ?? row.created_at;
      const occurredAt =
        typeof occurredAtValue === 'string' ? occurredAtValue : new Date(occurredAtValue).toISOString();
      const statusNormalized = row.status.toLowerCase();
      const type = statusNormalized === 'failed' ? 'scan.failed' : 'scan.completed';

      return {
        id: row.id,
        scan_id: row.id,
        project_id: row.project_id,
        project_name: row.project_name,
        status: row.status,
        policy_result: normalizePolicyResult(row.policy_result),
        occurred_at: occurredAt,
        type,
        links: {
          scan: `/v1/scans/${row.id}`,
          sbom: `/v1/sboms/${row.id}`
        }
      } as const;
    });

    return reply.send({ data: events });
  });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error instanceof ZodError) {
      const message = error.errors[0]?.message ?? 'Validation error.';
      return sendError(reply, request, 400, 'validation_error', message);
    }

    const statusCode = typeof error.statusCode === 'number' ? error.statusCode : 500;
    const code = statusCode >= 500 ? 'internal_error' : 'bad_request';
    const message = typeof error.message === 'string' ? error.message : 'Unexpected error.';

    return sendError(reply, request, statusCode, code, message);
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const config = await loadApiConfig(process.env);
    const port = Number(process.env.PORT ?? 3000);
    const host = process.env.HOST ?? '0.0.0.0';

    const pool: Pool = new Pool({ connectionString: config.databaseUrl });
    const db: Database = {
      async query<T>(text: string, values?: ReadonlyArray<unknown>) {
        const executeQuery = pool.query.bind(pool) as unknown as (
          queryText: string,
          queryValues?: ReadonlyArray<unknown>
        ) => Promise<{ rows: T[] }>;
        const result = await executeQuery(text, values);
        return { rows: result.rows };
      },
      async transaction<T>(handler: (client: DatabaseClient) => Promise<T>) {
        const client: PoolClient = await pool.connect();

        const transactionalClient: DatabaseClient = {
          query: async <R>(queryText: string, queryValues?: ReadonlyArray<unknown>) => {
            const result = await client.query(queryText, queryValues as unknown[]);
            return { rows: (result as { rows: R[] }).rows };
          }
        };

        try {
          await client.query('BEGIN');
          const result = await handler(transactionalClient);
          await client.query('COMMIT');
          return result;
        } catch (error) {
          try {
            await client.query('ROLLBACK');
          } catch {
            // ignore rollback failure
          }
          throw error;
        } finally {
          client.release();
        }
      }
    };

    const redisConnection = new Redis(config.redisUrl);
    const queue = new Queue(config.scanQueueName, { connection: redisConnection });

    buildServer({
      version: process.env.npm_package_version ?? '0.0.0-dev',
      db,
      queue,
      redis: redisConnection,
      metrics: defaultMetrics,
      apiKeySalt: config.apiKeySalt,
      licensePublicKey: config.licensePublicKey,
      telemetryEnabled: config.telemetryEnabled
    })
      .then((app) => app.listen({ port, host }))
      .then((address) => {
        console.log(`API server listening on ${address}`);
      })
      .catch((error: unknown) => {
        const failure = error instanceof Error ? error : new Error(String(error));
        console.error('API start failure', failure);
        process.exitCode = 1;
      });
  } catch (error) {
    const failure = error instanceof Error ? error : new Error(String(error));
    console.error('API configuration error', failure);
    process.exitCode = 1;
  }
}
