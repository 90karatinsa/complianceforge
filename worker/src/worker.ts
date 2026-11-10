// SPDX-License-Identifier: MIT

import { Worker as BullWorker, type Job } from 'bullmq';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { Buffer } from 'node:buffer';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { promises as fsPromises } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { Agent } from 'undici';
import { z } from 'zod';

import {
  cleanupWorkspace,
  fetchArtifact,
  type ArtifactDefinition,
  type PrivateAddressError
} from './fetcher.js';
import { buildEvidencePack as defaultBuildEvidencePack } from './evidence-pack.js';
import { deriveLicenseObligations } from './license-obligations.js';
import { runScanners, type OsvVulnerability, type ScannerResult } from './scanners.js';
import {
  evaluatePolicy as evaluatePolicyWithOpa,
  extractCvssScore,
  type PolicyRules
} from './policy-opa.js';
import { isNetworkFetchAllowed } from './network-guard.js';
import type { SiemDispatcher, SiemEvent } from './integrations/siem.js';
import { metrics as defaultMetrics, type Metrics } from '../../metrics/index.js';
import { getLicenseStatus, type LicenseStatusResult } from '../../scripts/license-manager.ts';
import { validateLicensePublicKey } from '../../scripts/license-public-key.ts';
import { createTracer, type Tracer, type SpanContext } from '../../observability/tracing.js';
import type { TicketingDispatcher, TicketingEvent } from './integrations/ticketing.js';
import { decryptWebhookSecret } from './webhook-crypto.js';

export interface DatabaseClient {
  query<T = unknown>(text: string, values?: ReadonlyArray<unknown>): Promise<{ rows: T[] }>;
}

export interface Database extends DatabaseClient {
  transaction<T>(handler: (client: DatabaseClient) => Promise<T>): Promise<T>;
}

export interface ScanJobData {
  readonly scan_id: string;
  readonly project_id: string;
  readonly artifact_id: string | null;
  readonly policy_id: string | null;
}

interface ScanRecord {
  readonly scan_id: string;
  readonly project_id: string;
  readonly artifact_id: string | null;
  readonly tenant_id: string;
  readonly policy_id: string | null;
  readonly artifact_type: ArtifactDefinition['type'];
  readonly artifact_ref: Record<string, unknown>;
  readonly artifact_metadata: Record<string, unknown> | null;
}

interface PolicyRow {
  readonly rules: PolicyRules;
}

interface PolicyExceptionRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly project_id: string | null;
  readonly component_purl: string | null;
  readonly scope: 'package' | 'project' | 'organization';
  readonly status: 'pending' | 'approved' | 'revoked' | 'expired';
  readonly expires_at: Date | string | null;
}

interface EncryptedWebhookRow {
  readonly id: string;
  readonly url: string;
  readonly secret_ciphertext: Buffer | null;
  readonly secret_iv: Buffer | null;
  readonly secret_auth_tag: Buffer | null;
  readonly secret_last_four: string | null;
  readonly events: string[] | null;
}

interface WebhookRow {
  readonly id: string;
  readonly url: string;
  readonly secret: string | null;
  readonly events: string[] | null;
}

interface WebhookFailure {
  readonly id: string;
  readonly error: string;
}

export const DEFAULT_WEBHOOK_ATTEMPTS = 3;
export const WEBHOOK_RETRY_BASE_MS = 500;
const WEBHOOK_REQUEST_TIMEOUT_MS = 10_000;
const WEBHOOK_CIRCUIT_FAILURE_THRESHOLD = 3;
const WEBHOOK_CIRCUIT_COOLDOWN_MS = 60_000;
const WEBHOOK_CACHE_TTL_MS = 60_000;
const OSV_CACHE_TTL_MS = 86_400_000; // 24 hours

export interface WorkerDependencies {
  readonly db: Database;
  readonly fetchArtifact: typeof fetchArtifact;
  readonly runScanners: typeof runScanners;
  readonly cleanupWorkspace: typeof cleanupWorkspace;
  readonly buildEvidencePack?: typeof defaultBuildEvidencePack;
  readonly metrics: Metrics;
  readonly fetchImpl: typeof fetch;
  readonly generateId: () => string;
  readonly now: () => Date;
  readonly wait: (ms: number) => Promise<void>;
  readonly webhookRetryAttempts: number;
  readonly webhookRetryBaseMs: number;
  readonly webhookSecretKey: Buffer;
  readonly random?: () => number;
  readonly scheduleRescan?: (input: { projectId: string; tenantId: string; reason: string }) => Promise<void>;
  readonly sendSiemEvent?: (event: SiemEvent) => Promise<void>;
  readonly syncTicketing?: (event: TicketingEvent) => Promise<void>;
  readonly tracer?: Tracer;
}

type UndiciAgentInstance = InstanceType<typeof Agent>;
type GuardedWebhookDispatcher = Pick<UndiciAgentInstance, 'dispatch' | 'close' | 'destroy'>;
type GuardedWebhookRequestOptions = NonNullable<Parameters<typeof fetch>[1]> & {
  readonly dispatcher: GuardedWebhookDispatcher;
};

type CircuitState = {
  failures: number;
  state: 'closed' | 'open' | 'half-open';
  openedAt: number;
  trialInProgress: boolean;
};

const webhookCircuitStates = new Map<string, CircuitState>();
const webhookCache = new Map<string, { webhooks: WebhookRow[]; expiresAt: number }>();

export function __testResetWebhookCircuitBreaker(): void {
  webhookCircuitStates.clear();
}

export function __testResetWebhookCache(): void {
  webhookCache.clear();
}

const PURGE_IGNORE_NAMES = new Set(['.git', '.cache', 'node_modules']);

async function hashFileSha256(filePath: string): Promise<string> {
  const hash = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve());
    stream.on('error', (error) => reject(error));
  });
  return hash.digest('hex');
}

function shouldIgnorePurgeEntry(relativePath: string): boolean {
  const segments = relativePath.split('/');
  return segments.some((segment) => PURGE_IGNORE_NAMES.has(segment));
}

async function createPurgeManifest(workspacePath: string): Promise<Record<string, unknown>> {
  const generatedAt = new Date().toISOString();
  try {
    await fsPromises.access(workspacePath);
  } catch (error) {
    return {
      generated_at: generatedAt,
      root: workspacePath,
      items: [],
      note: 'workspace_missing'
    } satisfies Record<string, unknown>;
  }

  const items: Array<Record<string, unknown>> = [];
  const queue: Array<{ dir: string; relative: string }> = [{ dir: workspacePath, relative: '.' }];

  while (queue.length > 0) {
    const current = queue.pop();
    if (!current) {
      break;
    }

    const directory = await fsPromises.opendir(current.dir);
    // eslint-disable-next-line no-await-in-loop
    for await (const entry of directory) {
      const relativePath = current.relative === '.' ? entry.name : `${current.relative}/${entry.name}`;

      if (shouldIgnorePurgeEntry(relativePath)) {
        continue;
      }

      const fullPath = join(current.dir, entry.name);
      if (entry.isDirectory()) {
        queue.push({ dir: fullPath, relative: relativePath });
        items.push({ path: `${relativePath}/`, type: 'directory' });
        continue;
      }

      if (entry.isFile()) {
        // eslint-disable-next-line no-await-in-loop
        const stats = await fsPromises.stat(fullPath);
        // eslint-disable-next-line no-await-in-loop
        const sha256 = await hashFileSha256(fullPath);
        items.push({ path: relativePath, type: 'file', bytes: stats.size, sha256 });
        continue;
      }

      items.push({ path: relativePath, type: entry.isSymbolicLink() ? 'symlink' : 'other' });
    }
  }

  const manifestPaths = new Set<string>();
  const dedupedItems = items.filter((item) => {
    const path = typeof item.path === 'string' ? item.path : null;
    if (!path || manifestPaths.has(path)) {
      return false;
    }
    manifestPaths.add(path);
    return true;
  });

  return {
    generated_at: generatedAt,
    root: workspacePath,
    items: dedupedItems
  } satisfies Record<string, unknown>;
}

const REQUIRED_SCAN_FEATURE = 'scan:execute';

function getCircuitKey(url: URL): string {
  return url.host.toLowerCase();
}

function allowCircuitAttempt(
  key: string,
  nowMs: number,
  cooldownMs: number,
  circuits: Map<string, CircuitState>
): boolean {
  const state = circuits.get(key);

  if (!state) {
    return true;
  }

  if (state.state === 'open') {
    if (nowMs - state.openedAt >= cooldownMs) {
      state.state = 'half-open';
      state.trialInProgress = false;
      circuits.set(key, state);
    } else {
      return false;
    }
  }

  if (state.state === 'half-open') {
    if (state.trialInProgress) {
      return false;
    }

    state.trialInProgress = true;
    circuits.set(key, state);
    return true;
  }

  return true;
}

function recordCircuitFailure(
  key: string,
  nowMs: number,
  threshold: number,
  circuits: Map<string, CircuitState>
): boolean {
  const existing = circuits.get(key);

  if (!existing) {
    circuits.set(key, {
      failures: 1,
      state: 'closed',
      openedAt: nowMs,
      trialInProgress: false
    });
    return false;
  }

  if (existing.state === 'half-open') {
    existing.state = 'open';
    existing.openedAt = nowMs;
    existing.failures = threshold;
    existing.trialInProgress = false;
    circuits.set(key, existing);
    return true;
  }

  if (existing.state === 'open') {
    existing.openedAt = nowMs;
    circuits.set(key, existing);
    return true;
  }

  existing.failures += 1;

  if (existing.failures >= threshold) {
    existing.state = 'open';
    existing.openedAt = nowMs;
    existing.trialInProgress = false;
    circuits.set(key, existing);
    return true;
  }

  circuits.set(key, existing);
  return false;
}

function recordCircuitSuccess(key: string, circuits: Map<string, CircuitState>): void {
  circuits.delete(key);
}

export interface WorkerRuntimeConfig {
  readonly databaseUrl: string;
  readonly redisUrl: string;
  readonly scanQueueName: string;
  readonly maxConcurrency: number;
  readonly scanTimeoutSeconds: number;
  readonly redisTls?: {
    readonly rejectUnauthorized?: boolean;
  };
  readonly telemetryEnabled: boolean;
  readonly webhookSecretKey: Buffer;
}

type EnvSource = Record<string, string | undefined>;

function createBooleanFlagSchema(field: string): z.ZodEffects<z.ZodString, boolean, string> {
  return z
    .string()
    .trim()
    .transform((value) => value.toLowerCase())
    .refine(
      (value) => value === 'true' || value === 'false' || value === '1' || value === '0',
      `${field} must be a boolean value.`
    )
    .transform((value) => value === 'true' || value === '1');
}

const RedisBooleanFlagSchema = createBooleanFlagSchema('REDIS_TLS_REJECT_UNAUTHORIZED');
const TelemetryBooleanFlagSchema = createBooleanFlagSchema('TELEMETRY_ENABLED');

const SECRETS_MANAGER_PREFIX = 'secretsmanager://';

interface SecretsManagerUri {
  readonly secretId: string;
  readonly property?: string;
}

type SecretsCache = Map<string, string>;

const workerSecretCache: SecretsCache = new Map();
let workerSecretsClient: SecretsManagerClient | null = null;

function getWorkerSecretsClient(): SecretsManagerClient {
  if (!workerSecretsClient) {
    workerSecretsClient = new SecretsManagerClient({});
  }

  return workerSecretsClient;
}

function parseWorkerSecretsUri(value: string): SecretsManagerUri {
  const remainder = value.slice(SECRETS_MANAGER_PREFIX.length);

  if (!remainder) {
    throw new Error('Secrets Manager URI must include a secret identifier.');
  }

  const [rawId, rawProperty] = remainder.split('#');
  const secretId = decodeURIComponent(rawId);

  if (!secretId) {
    throw new Error('Secrets Manager URI must include a non-empty secret identifier.');
  }

  const property = rawProperty ? decodeURIComponent(rawProperty) : undefined;
  return { secretId, property };
}

async function resolveWorkerSecret(value: string, field: string): Promise<string> {
  if (!value.startsWith(SECRETS_MANAGER_PREFIX)) {
    return value;
  }

  const cached = workerSecretCache.get(value);
  if (cached) {
    return cached;
  }

  const { secretId, property } = parseWorkerSecretsUri(value);

  try {
    const client = getWorkerSecretsClient();
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

    workerSecretCache.set(value, resolved);
    return resolved;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to resolve ${field} from AWS Secrets Manager: ${message}`);
  }
}

export function __testResetWorkerSecretCache(): void {
  workerSecretCache.clear();
  workerSecretsClient = null;
}

function decodeWorkerWebhookKey(value: string): Buffer {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error('WEBHOOK_SECRET_KEY must be configured.');
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(trimmed, 'base64');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`WEBHOOK_SECRET_KEY must be a base64-encoded 32-byte key. (${message})`);
  }

  const normalized = decoded.toString('base64').replace(/=+$/u, '');
  const candidate = trimmed.replace(/=+$/u, '');

  if (normalized !== candidate || decoded.length !== 32) {
    throw new Error('WEBHOOK_SECRET_KEY must be a base64-encoded 32-byte key.');
  }

  return decoded;
}

const WorkerConfigSchema = z.object({
  DATABASE_URL: z
    .string({ required_error: 'DATABASE_URL must be configured.' })
    .min(1, 'DATABASE_URL must be configured.'),
  REDIS_URL: z
    .string({ required_error: 'REDIS_URL must be configured.' })
    .min(1, 'REDIS_URL must be configured.'),
  SCAN_QUEUE_NAME: z
    .string({ required_error: 'SCAN_QUEUE_NAME must be configured.' })
    .min(1, 'SCAN_QUEUE_NAME must be configured.'),
  MAX_CONCURRENCY: z.coerce
    .number({ invalid_type_error: 'MAX_CONCURRENCY must be a positive integer.' })
    .int()
    .positive('MAX_CONCURRENCY must be a positive integer.'),
  SCAN_TIMEOUT_S: z.coerce
    .number({ invalid_type_error: 'SCAN_TIMEOUT_S must be a positive integer.' })
    .int()
    .positive('SCAN_TIMEOUT_S must be a positive integer.'),
  WEBHOOK_SECRET_KEY: z
    .string({ required_error: 'WEBHOOK_SECRET_KEY must be configured.' })
    .min(1, 'WEBHOOK_SECRET_KEY must be configured.'),
  REDIS_TLS_REJECT_UNAUTHORIZED: RedisBooleanFlagSchema.optional(),
  TELEMETRY_ENABLED: TelemetryBooleanFlagSchema.optional()
});

export async function loadWorkerConfig(env: EnvSource = process.env): Promise<WorkerRuntimeConfig> {
  const parsed = WorkerConfigSchema.parse(env);

  const [databaseUrl, redisUrl, webhookSecret] = await Promise.all([
    resolveWorkerSecret(parsed.DATABASE_URL, 'DATABASE_URL'),
    resolveWorkerSecret(parsed.REDIS_URL, 'REDIS_URL'),
    resolveWorkerSecret(parsed.WEBHOOK_SECRET_KEY, 'WEBHOOK_SECRET_KEY')
  ]);

  const redisTls =
    parsed.REDIS_TLS_REJECT_UNAUTHORIZED === undefined
      ? undefined
      : { rejectUnauthorized: parsed.REDIS_TLS_REJECT_UNAUTHORIZED };

  const webhookSecretKey = decodeWorkerWebhookKey(webhookSecret);

  return {
    databaseUrl,
    redisUrl,
    scanQueueName: parsed.SCAN_QUEUE_NAME,
    maxConcurrency: parsed.MAX_CONCURRENCY,
    scanTimeoutSeconds: parsed.SCAN_TIMEOUT_S,
    redisTls,
    telemetryEnabled: parsed.TELEMETRY_ENABLED ?? false,
    webhookSecretKey
  } as const;
}

let sharedRedisConnection: Redis | null = null;
let sharedRedisSignature: string | null = null;

function serializeRedisSignature(config: WorkerRuntimeConfig): string {
  const rejectUnauthorized = config.redisTls?.rejectUnauthorized;
  return `${config.redisUrl}::${rejectUnauthorized === undefined ? 'default' : rejectUnauthorized}`;
}

function getRedisConnection(config: WorkerRuntimeConfig): Redis {
  const signature = serializeRedisSignature(config);

  if (!sharedRedisConnection || sharedRedisSignature !== signature) {
    if (sharedRedisConnection) {
      void sharedRedisConnection.quit().catch(() => {});
    }

    const options = config.redisTls?.rejectUnauthorized !== undefined
      ? { tls: { rejectUnauthorized: config.redisTls.rejectUnauthorized } }
      : undefined;

    sharedRedisConnection = options ? new Redis(config.redisUrl, options) : new Redis(config.redisUrl);
    sharedRedisSignature = signature;
  }

  return sharedRedisConnection;
}

function defaultWait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function logSiemError(context: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[siem] ${context}: ${message}`);
}

type SeverityLevel = 'pass' | 'warn' | 'fail';

function classifyCvssScore(score: number | undefined): SeverityLevel {
  if (typeof score !== 'number' || Number.isNaN(score)) {
    return 'pass';
  }

  if (score >= 7) {
    return 'fail';
  }

  if (score >= 4) {
    return 'warn';
  }

  return 'pass';
}

function combineSeverity(a: SeverityLevel, b: SeverityLevel): SeverityLevel {
  const order: Record<SeverityLevel, number> = {
    pass: 0,
    warn: 1,
    fail: 2
  } as const;

  return order[a] >= order[b] ? a : b;
}

type TicketSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

function mapPolicyResultToTicketSeverity(result: SeverityLevel): TicketSeverity {
  if (result === 'fail') {
    return 'critical';
  }

  if (result === 'warn') {
    return 'medium';
  }

  return 'info';
}

function describeSeverity(score: number | undefined): string {
  if (typeof score !== 'number' || Number.isNaN(score)) {
    return 'unknown';
  }

  if (score >= 9) {
    return 'critical';
  }

  if (score >= 7) {
    return 'high';
  }

  if (score >= 4) {
    return 'medium';
  }

  if (score > 0) {
    return 'low';
  }

  return 'none';
}

function isPrivateIpv4(address: string): boolean {
  const octets = address.split('.').map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((octet) => Number.isNaN(octet) || octet < 0 || octet > 255)) {
    return false;
  }

  if (octets[0] === 10 || octets[0] === 127 || octets[0] === 0) {
    return true;
  }

  if (octets[0] === 192 && octets[1] === 168) {
    return true;
  }

  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
    return true;
  }

  if (octets[0] === 169 && octets[1] === 254) {
    return true;
  }

  const asInt = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  const carrierNatStart = (100 << 24) | (64 << 16);
  const carrierNatEnd = (100 << 24) | (127 << 16) | (255 << 8) | 255;
  return asInt >= carrierNatStart && asInt <= carrierNatEnd;
}

function extractIpv4FromMappedIpv6(address: string): string | null {
  const normalized = address.toLowerCase();

  if (!normalized.startsWith('::ffff:')) {
    return null;
  }

  const remainder = normalized.slice('::ffff:'.length);

  if (!remainder) {
    return null;
  }

  const segments = remainder.split(':').filter((segment) => segment.length > 0);
  const dotted = [...segments].reverse().find((segment) => segment.includes('.'));

  if (dotted) {
    return dotted;
  }

  if (segments.length >= 2) {
    const [highSegment, lowSegment] = segments.slice(-2);
    const high = Number.parseInt(highSegment, 16);
    const low = Number.parseInt(lowSegment, 16);

    if ([high, low].some((value) => Number.isNaN(value) || value < 0 || value > 0xffff)) {
      return null;
    }

    const octets = [
      (high >> 8) & 0xff,
      high & 0xff,
      (low >> 8) & 0xff,
      low & 0xff
    ];

    return octets.join('.');
  }

  return null;
}

function isPrivateIpv6(address: string): boolean {
  const normalized = address.toLowerCase();

  if (normalized === '::' || normalized === '::1') {
    return true;
  }

  if (normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80')) {
    return true;
  }

  const mappedIpv4 = extractIpv4FromMappedIpv6(normalized);

  if (mappedIpv4) {
    return isPrivateIpv4(mappedIpv4);
  }

  if (normalized.startsWith('::ffff:')) {
    return true;
  }

  return false;
}

function isPrivateAddress(address: string): boolean {
  return isPrivateIpv4(address) || isPrivateIpv6(address);
}

async function ensurePublicWebhookTarget(url: URL): Promise<void> {
  const hostname = url.hostname.trim();
  const normalizedHost =
    hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  const lowered = normalizedHost.toLowerCase();

  if (!normalizedHost) {
    throw new Error('Webhook URL must include a hostname.');
  }

  if (lowered === 'localhost' || lowered.endsWith('.local')) {
    throw new Error('Webhook URL resolves to a private address.');
  }

  if (isIP(normalizedHost)) {
    if (isPrivateAddress(normalizedHost)) {
      throw new Error('Webhook URL resolves to a private address.');
    }
    return;
  }

  const records = await lookup(normalizedHost, { all: true });
  if (records.length === 0) {
    throw new Error('Webhook host could not be resolved.');
  }

  for (const record of records) {
    if (isPrivateAddress(record.address)) {
      throw new Error('Webhook URL resolves to a private address.');
    }
  }
}

type GuardedWebhookLookupCallback = (
  error: PrivateAddressError | null,
  address?: string,
  family?: number
) => void;

function createWebhookGuardedLookup(context: string) {
  return (
    hostname: string,
    options: { family?: number; hints?: number; all?: boolean },
    callback: GuardedWebhookLookupCallback
  ): void => {
    lookup(hostname, { family: options.family, hints: options.hints, all: true })
      .then((records) => {
        const allowed = records.find((record) => !isPrivateAddress(record.address));

        if (!allowed) {
          const error: PrivateAddressError = new Error(`${context} resolves to a private address.`);
          error.code = 'ERR_PRIVATE_ADDRESS';
          callback(error);
          return;
        }

        callback(null, allowed.address, allowed.family ?? (allowed.address.includes(':') ? 6 : 4));
      })
      .catch((error) => {
        const normalizedError: PrivateAddressError =
          error instanceof Error ? (error as PrivateAddressError) : new Error(String(error));
        callback(normalizedError);
      });
  };
}

async function createPublicWebhookDispatcher(url: URL): Promise<GuardedWebhookDispatcher> {
  await ensurePublicWebhookTarget(url);
  const rawHostname = url.hostname.trim();
  const normalizedHost =
    rawHostname.startsWith('[') && rawHostname.endsWith(']')
      ? rawHostname.slice(1, -1)
      : rawHostname;

  if (isIP(normalizedHost)) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
    const agent: UndiciAgentInstance = new Agent({
      connect: {
        lookup: (
          _hostname: string,
          _options: { family?: number; hints?: number; all?: boolean },
          callback: GuardedWebhookLookupCallback
        ): void => {
          callback(null, normalizedHost, normalizedHost.includes(':') ? 6 : 4);
        }
      }
    });

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return agent;
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
  const agent: UndiciAgentInstance = new Agent({
    connect: {
      lookup: createWebhookGuardedLookup('Webhook URL')
    }
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return agent;
}

function shouldDeliverWebhook(webhook: WebhookRow, eventName: string): boolean {
  const events = webhook.events;

  if (!Array.isArray(events) || events.length === 0) {
    return true;
  }

  const normalized = events.map((value) => value.toLowerCase());
  const target = eventName.toLowerCase();
  return (
    normalized.includes(target) ||
    normalized.includes('scan.*') ||
    normalized.includes('*') ||
    normalized.includes('all')
  );
}

async function deliverWebhook(
  webhook: WebhookRow,
  eventName: string,
  payload: Record<string, unknown>,
  dependencies: WorkerDependencies,
  parentContext: SpanContext | null = null
): Promise<WebhookFailure | null> {
  if (!shouldDeliverWebhook(webhook, eventName)) {
    return null;
  }

  const tracer = dependencies.tracer;
  const span = tracer?.startSpan('worker.deliver_webhook', {
    parentContext,
    attributes: {
      webhook_id: webhook.id,
      event: eventName
    }
  });

  try {
    let targetUrl: URL;
    try {
      targetUrl = new URL(webhook.url);
    } catch (error) {
      dependencies.metrics.webhookOutcomeCounter.inc({ result: 'failed' });
      span?.setStatus('error', 'Webhook URL is invalid.');
      span?.recordException(error);
      return {
        id: webhook.id,
        error: 'Webhook URL is invalid.'
      };
    }

    span?.setAttribute('webhook.url', targetUrl.toString());

    if (targetUrl.protocol !== 'https:') {
      dependencies.metrics.webhookOutcomeCounter.inc({ result: 'failed' });
      span?.setStatus('error', 'Webhook URL must use HTTPS.');
      return {
        id: webhook.id,
        error: 'Webhook URL must use HTTPS.'
      };
    }

    const circuitKey = getCircuitKey(targetUrl);
    span?.setAttribute('webhook.host', circuitKey);
    const circuitNow = dependencies.now().getTime();

    if (
      !allowCircuitAttempt(
        circuitKey,
        circuitNow,
        WEBHOOK_CIRCUIT_COOLDOWN_MS,
        webhookCircuitStates
      )
    ) {
      dependencies.metrics.webhookOutcomeCounter.inc({ result: 'failed' });
      span?.setStatus('error', 'Webhook circuit open');
      return {
        id: webhook.id,
        error: 'Webhook delivery temporarily disabled due to repeated failures. Try again later.'
      };
    }

    let dispatcher: GuardedWebhookDispatcher;
    try {
      dispatcher = await createPublicWebhookDispatcher(targetUrl);
    } catch (error) {
      dependencies.metrics.webhookOutcomeCounter.inc({ result: 'failed' });
      const message = error instanceof Error ? error.message : 'Webhook URL resolves to a private address.';
      span?.setStatus('error', message);
      span?.recordException(error);
      return {
        id: webhook.id,
        error: message
      };
    }

    const attempts = Math.max(1, dependencies.webhookRetryAttempts);
    const body = JSON.stringify(payload);
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'X-Otomatik-Webhook-Id': webhook.id,
      'X-Otomatik-Webhook-Event': eventName
    };

    if (webhook.secret) {
      const signature = createHmac('sha256', webhook.secret).update(body).digest('hex');
      headers['X-Webhook-Signature'] = `sha256=${signature}`;
    }

    if (span) {
      const carrier: Record<string, string> = {};
      tracer?.inject(carrier, span.context);
      if (carrier.traceparent) {
        headers.traceparent = carrier.traceparent;
      }
    }

    let attempt = 0;
    let lastError: Error | null = null;

    try {
      while (attempt < attempts) {
        attempt += 1;
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), WEBHOOK_REQUEST_TIMEOUT_MS);
          try {
            const response = await dependencies.fetchImpl(targetUrl.toString(), {
              method: 'POST',
              headers,
              body,
              signal: controller.signal,
              redirect: 'manual',
              dispatcher
            } as GuardedWebhookRequestOptions);

            if (response.status >= 300 && response.status < 400) {
              throw new Error(`Webhook attempted redirect with status ${response.status}`);
            }

            if (!response.ok) {
              throw new Error(`Webhook responded with status ${response.status}`);
            }

            dependencies.metrics.webhookOutcomeCounter.inc({ result: 'success' });
            recordCircuitSuccess(circuitKey, webhookCircuitStates);
            span?.setStatus('ok');
            return null;
          } finally {
            clearTimeout(timer);
          }
        } catch (error) {
          const reason = error instanceof Error ? error : new Error(String(error));
          if (reason.name === 'AbortError') {
            lastError = new Error('Webhook request timed out.');
          } else {
            lastError = reason;
          }

          const opened = recordCircuitFailure(
            circuitKey,
            dependencies.now().getTime(),
            WEBHOOK_CIRCUIT_FAILURE_THRESHOLD,
            webhookCircuitStates
          );

          if (opened || attempt >= attempts) {
            break;
          }

          const random = dependencies.random ?? Math.random;
          const baseDelay = dependencies.webhookRetryBaseMs * 2 ** (attempt - 1);
          const jitterFactor = 0.75 + random() * 0.5;
          const delay = Math.max(1, Math.round(baseDelay * jitterFactor));
          await dependencies.wait(delay);
        }
      }
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      await dispatcher.close();
    }

    dependencies.metrics.webhookOutcomeCounter.inc({ result: 'failed' });
    if (!lastError) {
      recordCircuitFailure(
        circuitKey,
        dependencies.now().getTime(),
        WEBHOOK_CIRCUIT_FAILURE_THRESHOLD,
        webhookCircuitStates
      );
    }
    const errorMessage = lastError?.message ?? 'Unknown webhook error';
    if (lastError) {
      span?.recordException(lastError);
    }
    span?.setStatus('error', errorMessage);
    return {
      id: webhook.id,
      error: errorMessage
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    span?.setStatus('error', message);
    span?.recordException(error);
    throw error;
  } finally {
    span?.end();
  }
}

export async function processScanJob(
  data: ScanJobData,
  dependencies: WorkerDependencies
): Promise<void> {
  const timer = dependencies.metrics.scanDurationHistogram.startTimer();
  let workspacePath: string | undefined;
  const startTime = dependencies.now();
  const startedAt = startTime.toISOString();
  let record: ScanRecord | undefined;
  let webhooks: WebhookRow[] = [];
  let rescanNeeded = false;
  let downgradedByVex = 0;
  const tracer = dependencies.tracer;
  const rootSpan = tracer?.startSpan('worker.process_scan', {
    attributes: {
      scan_id: data.scan_id,
      project_id: data.project_id,
      artifact_id: data.artifact_id ?? null
    }
  });

  try {
    await dependencies.db.query('UPDATE scans SET status = $2, started_at = $3 WHERE id = $1', [
      data.scan_id,
      'running',
      startedAt
    ]);

    const scanResult = await dependencies.db.query<ScanRecord>(
      `SELECT s.id AS scan_id, s.project_id, s.artifact_id, s.policy_id, p.tenant_id,
              a.type AS artifact_type, a.ref AS artifact_ref, a.metadata AS artifact_metadata
         FROM scans s
         INNER JOIN projects p ON p.id = s.project_id
         INNER JOIN artifacts a ON a.id = s.artifact_id
        WHERE s.id = $1
        LIMIT 1`,
      [data.scan_id]
    );

    record = scanResult.rows[0];

    if (!record) {
      throw new Error(`Scan ${data.scan_id} could not be loaded.`);
    }

    rootSpan?.setAttribute('tenant_id', record.tenant_id);

    if (!record.artifact_id) {
      throw new Error(`Scan ${data.scan_id} is missing an artifact reference.`);
    }

    const activeRecord = record;

    let activeFeedVersion: string | null = null;

    const tenantMetadataResult = await dependencies.db.query<{ metadata: Record<string, unknown> }>(
      'SELECT metadata FROM tenants WHERE id = $1 LIMIT 1',
      [activeRecord.tenant_id]
    );

    const tenantMetadata = tenantMetadataResult.rows[0]?.metadata ?? {};
    const feedVersionCandidate =
      tenantMetadata && typeof tenantMetadata === 'object'
        ? (tenantMetadata as Record<string, unknown>).active_feed_version
        : null;

    if (typeof feedVersionCandidate === 'string') {
      activeFeedVersion = feedVersionCandidate;
    }

    const artifactDefinition: ArtifactDefinition = {
      type: activeRecord.artifact_type,
      ref: activeRecord.artifact_ref,
      metadata: activeRecord.artifact_metadata ?? {}
    };

    const webhookCacheKey = activeRecord.tenant_id;
    const nowMs = dependencies.now().getTime();
    const cachedEntry = webhookCache.get(webhookCacheKey);
    let cacheStatus: 'hit' | 'miss' = 'miss';
    let cacheCandidate: { webhooks: WebhookRow[]; expiresAt: number } | null = null;

    if (cachedEntry && cachedEntry.expiresAt > nowMs) {
      cacheStatus = 'hit';
      webhooks = cachedEntry.webhooks.map((entry) => ({ ...entry }));
    } else {
      const webhookRows = await dependencies.db.query<EncryptedWebhookRow>(
        'SELECT id, url, secret_ciphertext, secret_iv, secret_auth_tag, secret_last_four, events FROM webhooks WHERE tenant_id = $1',
        [webhookCacheKey]
      );

      try {
        const decrypted = webhookRows.rows.map((row) => {
          const secret = decryptWebhookSecret(
            row.secret_ciphertext ?? null,
            row.secret_iv ?? null,
            row.secret_auth_tag ?? null,
            dependencies.webhookSecretKey
          );

          return {
            id: row.id,
            url: row.url,
            secret,
            events: row.events
          } satisfies WebhookRow;
        });

        webhooks = decrypted;
        cacheCandidate = {
          webhooks: decrypted.map((row) => ({ ...row })),
          expiresAt: nowMs + WEBHOOK_CACHE_TTL_MS
        };
      } catch (error) {
        webhookCache.delete(webhookCacheKey);
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Failed to decrypt webhook secret: ${message}`);
      }
    }

    rootSpan?.setAttribute('worker.webhooks.cache', cacheStatus);

    const fetchSpan = tracer?.startSpan('worker.fetch_artifact', {
      parentContext: rootSpan?.context ?? null,
      attributes: { artifact_type: artifactDefinition.type }
    });
    const fetchResult = await dependencies
      .fetchArtifact({
        scanId: data.scan_id,
        artifact: artifactDefinition
      })
      .catch((error) => {
        fetchSpan?.setStatus('error', error instanceof Error ? error.message : String(error));
        fetchSpan?.recordException(error);
        throw error;
      });
    fetchSpan?.setStatus('ok');
    fetchSpan?.end();
    workspacePath = fetchResult.workspacePath;

    const osvCache = new Map<string, OsvVulnerability[]>();
    if (activeFeedVersion) {
      const cacheResult = await dependencies.db.query<{
        package_purl: string;
        vulnerabilities: OsvVulnerability[];
        fetched_at: Date | string | null;
      }>(
        'SELECT package_purl, vulnerabilities, fetched_at FROM osv_cache WHERE tenant_id = $1 AND feed_version = $2',
        [activeRecord.tenant_id, activeFeedVersion]
      );
      const nowMs = dependencies.now().getTime();
      const expirationCutoff = new Date(nowMs - OSV_CACHE_TTL_MS);
      const allowNetworkFetch = isNetworkFetchAllowed();
      let hasExpiredEntries = false;
      for (const row of cacheResult.rows) {
        if (!row.package_purl) {
          continue;
        }
        const fetchedAt = row.fetched_at ? new Date(row.fetched_at) : null;
        const fetchedMs = fetchedAt?.getTime() ?? Number.NaN;
        const isFresh = !Number.isNaN(fetchedMs) && nowMs - fetchedMs <= OSV_CACHE_TTL_MS;

        if (isFresh || !allowNetworkFetch) {
          const entries = Array.isArray(row.vulnerabilities) ? row.vulnerabilities : [];
          osvCache.set(row.package_purl, entries);
        }

        if (!isFresh && allowNetworkFetch) {
          hasExpiredEntries = true;
        }
      }

      if (hasExpiredEntries && allowNetworkFetch) {
        await dependencies.db.query(
          'DELETE FROM osv_cache WHERE tenant_id = $1 AND feed_version = $2 AND (fetched_at IS NULL OR fetched_at < $3)',
          [activeRecord.tenant_id, activeFeedVersion, expirationCutoff]
        );
      }
    }

    const scannerSpan = tracer?.startSpan('worker.run_scanners', {
      parentContext: rootSpan?.context ?? null
    });
    const scannerResult = await dependencies
      .runScanners(fetchResult.artifactPath, {
        ociLayersPath: artifactDefinition.type === 'oci' ? fetchResult.artifactPath : undefined,
        fetchImpl: dependencies.fetchImpl,
        cache: osvCache,
        now: dependencies.now,
        persistCache:
          activeFeedVersion
            ? async (packageKey, vulnerabilities) => {
                await dependencies.db.query(
                  `INSERT INTO osv_cache (tenant_id, package_purl, feed_version, vulnerabilities, fetched_at)
                     VALUES ($1, $2, $3, $4, NOW())
                     ON CONFLICT (tenant_id, package_purl, feed_version)
                     DO UPDATE SET vulnerabilities = EXCLUDED.vulnerabilities, fetched_at = EXCLUDED.fetched_at`,
                  [activeRecord.tenant_id, packageKey, activeFeedVersion, vulnerabilities]
                );
              }
            : undefined
      })
      .catch((error) => {
        scannerSpan?.setStatus('error', error instanceof Error ? error.message : String(error));
        scannerSpan?.recordException(error);
        throw error;
      });
    scannerSpan?.setStatus('ok');
    scannerSpan?.end();

    const sbomId = dependencies.generateId();
    const sbomFormat = scannerResult.bom?.bomFormat ?? 'CycloneDX';
    const componentCount = Array.isArray(scannerResult.bom?.components)
      ? scannerResult.bom.components.length
      : scannerResult.packages.length;

    type TransactionResult = {
      findingsSummary: {
        packages: number;
        licenses: number;
        vulnerabilities: number;
        policy: { result: SeverityLevel; reasons: string[] };
        duration_ms: number;
        webhooks: { delivered: number; failed: number; failures: WebhookFailure[] };
        vex: { downgraded: number; total: number };
      };
      webhookPayload: Record<string, unknown>;
      policyResult: SeverityLevel;
      policyReasons: string[];
      policyExceptions: PolicyExceptionRow[];
      vulnerabilityCount: number;
      completedAt: string;
    };
    const transactionSpan = tracer?.startSpan('worker.persist_results', {
      parentContext: rootSpan?.context ?? null
    });
    let transactionResult: TransactionResult | undefined;
    try {
      transactionResult = await dependencies.db.transaction<TransactionResult>(
        async (transactionDb) => {
      await transactionDb.query(
        `INSERT INTO sboms (id, project_id, artifact_id, scan_id, format, bom, component_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          sbomId,
          activeRecord.project_id,
          activeRecord.artifact_id,
          data.scan_id,
          sbomFormat,
          scannerResult.bom,
          componentCount
        ]
      );

      const packagesByName = new Map<string, string>();
      for (const pkg of scannerResult.packages) {
        packagesByName.set(pkg.name, pkg.purl);
      }

      for (const license of scannerResult.licenses) {
        const licenseId = dependencies.generateId();
        const componentPurl =
          (license.packageName ? packagesByName.get(license.packageName) : undefined) ?? `file:${license.path}`;
        const evidence = {
          path: license.path,
          component: license.packageName ?? null,
          spdx: license.spdxId ?? null
        };

        await transactionDb.query(
          `INSERT INTO licenses (id, sbom_id, component_purl, detected_spdx_id, evidence)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            licenseId,
            sbomId,
            componentPurl,
            license.spdxId ?? null,
            evidence
          ]
        );

        const obligations = deriveLicenseObligations({ spdxId: license.spdxId ?? null });
        const findingId = dependencies.generateId();

        await transactionDb.query(
          `INSERT INTO legal_findings (id, tenant_id, license_id, scan_id, status, obligations, notes)
           VALUES ($1, $2, $3, $4, 'pending', $5, $6)`,
          [
            findingId,
            activeRecord.tenant_id,
            licenseId,
            data.scan_id,
            obligations,
            null
          ]
        );
      }

      const componentPurls = scannerResult.packages.map((pkg) => pkg.purl);
      const exceptionResult = await transactionDb.query<PolicyExceptionRow>(
        `SELECT id, tenant_id, project_id, component_purl, scope, status, expires_at
           FROM policy_exceptions
          WHERE tenant_id = $1
            AND status IN ('pending', 'approved')
            AND (
              scope = 'organization'
              OR (scope = 'project' AND project_id = $2)
              OR (scope = 'package' AND component_purl = ANY($3::text[]))
            )
          ORDER BY created_at ASC`,
        [activeRecord.tenant_id, activeRecord.project_id, componentPurls]
      );

      const vexResult = await transactionDb.query<{ component_purl: string; status: string }>(
        `SELECT component_purl, status
           FROM vex_statements
          WHERE tenant_id = $1
            AND component_purl = ANY($2::text[])`,
        [activeRecord.tenant_id, componentPurls]
      );

      const vexStates = new Map<string, string>();

      for (const row of vexResult.rows) {
        if (row.component_purl) {
          vexStates.set(row.component_purl, (row.status ?? '').toLowerCase());
        }
      }

      const expiredExceptionIds: string[] = [];
      const activeExceptions: PolicyExceptionRow[] = [];
      const nowTime = startTime.getTime();

      for (const exception of exceptionResult.rows) {
        const expiresAt = exception.expires_at ? new Date(exception.expires_at).getTime() : null;
        const isExpired = typeof expiresAt === 'number' && expiresAt <= nowTime;

        if (isExpired && exception.status !== 'expired') {
          expiredExceptionIds.push(exception.id);
        } else if (!isExpired && exception.status === 'approved') {
          activeExceptions.push(exception);
        }
      }

      if (expiredExceptionIds.length > 0) {
        await transactionDb.query(
          `UPDATE policy_exceptions
              SET status = 'expired',
                  updated_at = NOW()
            WHERE id = ANY($1::uuid[])`,
          [expiredExceptionIds]
        );
        rescanNeeded = true;
      }

      let vulnerabilityCount = 0;
      let maxCvssScore: number | undefined;

      for (const finding of scannerResult.vulnerabilities) {
        for (const vulnerability of finding.vulnerabilities) {
          vulnerabilityCount += 1;
          const vulnId = dependencies.generateId();
          const severityScore = extractCvssScore(vulnerability);

          if (typeof severityScore === 'number' && Number.isFinite(severityScore)) {
            maxCvssScore = typeof maxCvssScore === 'number' ? Math.max(maxCvssScore, severityScore) : severityScore;
          }

          const cveAlias = Array.isArray((vulnerability as { aliases?: string[] }).aliases)
            ? (vulnerability as { aliases?: string[] }).aliases?.find((alias) =>
                typeof alias === 'string' && alias.toUpperCase().startsWith('CVE-')
              ) ?? null
            : null;
          const cveId = cveAlias
            ? cveAlias
            : typeof vulnerability.id === 'string' && vulnerability.id.toUpperCase().startsWith('CVE-')
              ? vulnerability.id
              : null;

          const vexState = vexStates.get(finding.package.purl);
          if (vexState === 'not_affected') {
            downgradedByVex += 1;
          }

          await transactionDb.query(
            `INSERT INTO vulns (id, scan_id, component_purl, source, cve_id, severity, cvss, summary, fixed_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
              vulnId,
              data.scan_id,
              finding.package.purl,
              'osv',
              cveId,
              describeSeverity(severityScore),
              severityScore ?? null,
              vulnerability.summary ?? null,
              null
            ]
          );
        }
      }

      let policyResult: SeverityLevel = classifyCvssScore(maxCvssScore);
      const policyReasons: string[] = [];

      if (policyResult !== 'pass' && typeof maxCvssScore === 'number') {
        policyReasons.push(`Detected vulnerability with CVSS ${maxCvssScore.toFixed(1)}.`);
      }

      if (activeRecord.policy_id) {
        const policyRows = await transactionDb.query<PolicyRow>(
          'SELECT rules FROM policies WHERE id = $1 LIMIT 1',
          [activeRecord.policy_id]
        );
        const policy = policyRows.rows[0];

        if (policy?.rules) {
          const evaluation = await evaluatePolicyWithOpa({
            rules: policy.rules,
            scannerResult,
            fetchImpl: dependencies.fetchImpl
          });
          const evaluationSeverity: SeverityLevel = evaluation.result === 'fail' ? 'fail' : 'pass';
          policyResult = combineSeverity(policyResult, evaluationSeverity);
          policyReasons.push(...evaluation.reasons);
        }
      }

      if (policyResult === 'fail' && activeExceptions.length > 0) {
        const scopes = Array.from(new Set(activeExceptions.map((exception) => exception.scope))).join(', ');
        policyReasons.push(`Policy exception applied (${scopes}).`);
        policyResult = 'warn';
      }

      const completedAtDate = dependencies.now();
      const completedAt = completedAtDate.toISOString();
      const durationMs = Math.max(0, completedAtDate.getTime() - startTime.getTime());

      const webhookPayload = {
        event: 'scan.completed',
        data: {
          scan_id: data.scan_id,
          status: 'succeeded',
          policy_result: policyResult,
          project_id: activeRecord.project_id,
          artifact_id: activeRecord.artifact_id,
          duration_ms: durationMs,
          findings: {
            packages: scannerResult.packages.length,
            licenses: scannerResult.licenses.length,
            vulnerabilities: vulnerabilityCount,
            vex: {
              downgraded: downgradedByVex,
              total: vulnerabilityCount
            },
            policy: {
              result: policyResult,
              reasons: policyReasons
            }
          }
        }
      } satisfies Record<string, unknown>;

      const findingsSummary = {
        packages: scannerResult.packages.length,
        licenses: scannerResult.licenses.length,
        vulnerabilities: vulnerabilityCount,
        policy: {
          result: policyResult,
          reasons: policyReasons
        },
        duration_ms: durationMs,
        webhooks: {
          delivered: 0,
          failed: 0,
          failures: [] as WebhookFailure[]
        },
        vex: {
          downgraded: downgradedByVex,
          total: vulnerabilityCount
        }
      };

      await transactionDb.query(
        `UPDATE scans
            SET status = $2,
                policy_result = $3,
                findings = $4,
                duration_ms = $5,
                completed_at = $6
          WHERE id = $1`,
        [data.scan_id, 'succeeded', policyResult, findingsSummary, durationMs, completedAt]
      );

          return {
            findingsSummary,
            webhookPayload,
            policyResult,
            policyReasons,
            policyExceptions: activeExceptions.map((exception) => ({ ...exception })),
            vulnerabilityCount,
            completedAt
          } satisfies TransactionResult;
        }
      );
      transactionSpan?.setStatus('ok');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      transactionSpan?.setStatus('error', message);
      transactionSpan?.recordException(error);
      throw error;
    } finally {
      transactionSpan?.end();
    }

    if (!transactionResult) {
      throw new Error('Scan persistence failed.');
    }

    const {
      findingsSummary,
      webhookPayload,
      policyResult: transactionPolicyResult,
      policyReasons: transactionPolicyReasons,
      policyExceptions,
      vulnerabilityCount: transactionVulnerabilityCount,
      completedAt
    } = transactionResult;

    const policyResult = transactionPolicyResult;
    const policyReasons = transactionPolicyReasons;
    const vulnerabilityCount = transactionVulnerabilityCount;

    const webhookFailures: WebhookFailure[] = [];

    for (const webhook of webhooks) {
      const failure = await deliverWebhook(
        webhook,
        'scan.completed',
        webhookPayload,
        dependencies,
        rootSpan?.context ?? null
      );
      if (failure) {
        webhookFailures.push(failure);
      }
    }

    if (webhookFailures.length > 0) {
      webhookCache.delete(webhookCacheKey);
    } else if (cacheCandidate) {
      webhookCache.set(webhookCacheKey, cacheCandidate);
    }

    const finalFindingsSummary = {
      ...findingsSummary,
      webhooks: {
        delivered: webhooks.length - webhookFailures.length,
        failed: webhookFailures.length,
        failures: webhookFailures
      }
    } satisfies typeof findingsSummary;

    await dependencies.db.query(
      `UPDATE scans
          SET findings = jsonb_set(findings::jsonb, '{webhooks}', $2::jsonb, true)
        WHERE id = $1`,
      [data.scan_id, finalFindingsSummary.webhooks]
    );

    let purgeManifest: Record<string, unknown> | null = null;
    if (workspacePath) {
      try {
        purgeManifest = await createPurgeManifest(workspacePath);
      } catch (error) {
        console.warn('Failed to generate purge manifest', error);
      }
    }

    const bundler = dependencies.buildEvidencePack ?? defaultBuildEvidencePack;
    const evidencePack = await bundler({
      tenantId: activeRecord.tenant_id,
      projectId: activeRecord.project_id,
      scanId: data.scan_id,
      feedVersion: activeFeedVersion,
      noticeVersionId: null,
      entries: [
        { path: 'sbom.cyclonedx.json', data: scannerResult.bom ?? {}, mediaType: 'application/json' },
        { path: 'packages.json', data: scannerResult.packages, mediaType: 'application/json' },
        { path: 'licenses.json', data: scannerResult.licenses, mediaType: 'application/json' },
        { path: 'vulnerabilities.json', data: scannerResult.vulnerabilities, mediaType: 'application/json' },
        {
          path: 'policy-evaluation.json',
          data: { result: policyResult, reasons: policyReasons },
          mediaType: 'application/json'
        },
        { path: 'exceptions.json', data: policyExceptions, mediaType: 'application/json' },
        { path: 'findings-summary.json', data: finalFindingsSummary, mediaType: 'application/json' },
        {
          path: 'feed-info.json',
          data: { active_feed_version: activeFeedVersion },
          mediaType: 'application/json'
        }
      ],
      purgeManifest
    });

    await dependencies.db.query(
      `INSERT INTO evidence_packs (tenant_id, project_id, scan_id, storage_path, manifest, signature, hash_algorithm)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (tenant_id, scan_id) DO UPDATE
         SET storage_path = EXCLUDED.storage_path,
             manifest = EXCLUDED.manifest,
             signature = EXCLUDED.signature,
             hash_algorithm = EXCLUDED.hash_algorithm`,
      [
        activeRecord.tenant_id,
        activeRecord.project_id,
        data.scan_id,
        null,
        evidencePack.manifest,
        evidencePack.signature?.value ?? null,
        evidencePack.hashAlgorithm
      ]
    );

    dependencies.metrics.vexNoiseGauge.set({ total: findingsSummary.vulnerabilities, downgraded: downgradedByVex });
    if (downgradedByVex > 0) {
      dependencies.metrics.vexDowngradedCounter.inc(downgradedByVex);
    }

    if (dependencies.sendSiemEvent) {
      const metadata: Record<string, unknown> = {
        feed_version: activeFeedVersion,
        policy_reasons: policyReasons,
        policy_exceptions: policyExceptions.map((exception) => exception.id)
      };

      await dependencies
        .sendSiemEvent({
          type: 'scan.completed',
          tenantId: activeRecord.tenant_id,
          projectId: activeRecord.project_id,
          scanId: data.scan_id,
          policyResult,
          totalVulnerabilities: vulnerabilityCount,
          downgradedByVex,
          timestamp: completedAt,
          metadata
        })
        .catch((error) => {
          logSiemError('scan.completed dispatch failed', error);
        });
    }

    if (dependencies.syncTicketing) {
      const action: TicketingEvent['action'] = policyResult === 'fail' ? 'open' : 'resolve';
      const severity = mapPolicyResultToTicketSeverity(policyResult);
      const reasons = policyReasons.length > 0 ? policyReasons : ['no_policy_reasons'];
      const summary = `Policy ${policyResult.toUpperCase()} for project ${activeRecord.project_id}`;
      const descriptionParts = [
        `Scan ${data.scan_id} completed with result ${policyResult}.`,
        `Exceptions applied: ${policyExceptions.length}`,
        `Reasons: ${reasons.join(', ')}`
      ];

      await dependencies
        .syncTicketing({
          action,
          tenantId: activeRecord.tenant_id,
          projectId: activeRecord.project_id,
          scanId: data.scan_id,
          summary,
          description: descriptionParts.join(' '),
          severity,
          reasons,
          idempotencyKey: `${activeRecord.project_id}:${data.scan_id}:${policyResult}`,
          referenceId: activeRecord.project_id
        })
        .catch((error) => {
          console.error('Ticket automation failed', error);
        });
    }

    if (rescanNeeded && dependencies.scheduleRescan && record) {
      await dependencies.scheduleRescan({
        projectId: record.project_id,
        tenantId: record.tenant_id,
        reason: 'policy_exception_expired'
      });
    }

    rootSpan?.setAttribute('policy_result', policyResult);
    rootSpan?.setAttribute('vulnerabilities.total', vulnerabilityCount);
    rootSpan?.setAttribute('vex.downgraded', downgradedByVex);
    rootSpan?.setStatus('ok');
    timer({ status: 'succeeded' });
  } catch (error) {
    const failureError = error instanceof Error ? error : new Error(String(error));
    const completedAtDate = dependencies.now();
    const completedAt = completedAtDate.toISOString();
    const durationMs = Math.max(0, completedAtDate.getTime() - startTime.getTime());

    await dependencies.db.query(
      'UPDATE scans SET status = $2, completed_at = $3, findings = $4, duration_ms = $5 WHERE id = $1',
      [
        data.scan_id,
        'failed',
        completedAt,
        { error: failureError.message },
        durationMs
      ]
    );

    if (dependencies.sendSiemEvent && record) {
      await dependencies
        .sendSiemEvent({
          type: 'scan.failed',
          tenantId: record.tenant_id,
          projectId: record.project_id,
          scanId: data.scan_id,
          policyResult: 'error',
          totalVulnerabilities: 0,
          downgradedByVex: 0,
          timestamp: completedAt,
          metadata: { error: failureError.message }
        })
        .catch((error) => {
          logSiemError('scan.failed dispatch failed', error);
        });
    }

    if (record && webhooks.length > 0) {
      const payload = {
        event: 'scan.failed',
        data: {
          scan_id: data.scan_id,
          status: 'failed',
          project_id: record.project_id,
          artifact_id: record.artifact_id,
          error: failureError.message,
          duration_ms: durationMs
        }
      } satisfies Record<string, unknown>;

      for (const webhook of webhooks) {
        await deliverWebhook(
          webhook,
          'scan.failed',
          payload,
          dependencies,
          rootSpan?.context ?? null
        );
      }
    }

    rootSpan?.setStatus('error', failureError.message);
    rootSpan?.recordException(failureError);
    timer({ status: 'failed' });
    throw failureError;
  } finally {
    if (workspacePath) {
      const endPurgeTimer = dependencies.metrics.purgeDurationHistogram.startTimer();
      await dependencies
        .cleanupWorkspace(workspacePath)
        .catch((cleanupError) => {
          console.error('Workspace cleanup failed', cleanupError);
        })
        .finally(() => {
          endPurgeTimer();
        });
    }
    rootSpan?.end();
  }
}

interface WorkerOptions {
  readonly queueName?: string;
  readonly connection?: Redis;
  readonly db?: Database;
  readonly metrics?: Metrics;
  readonly fetchArtifactImpl?: typeof fetchArtifact;
  readonly runScannersImpl?: typeof runScanners;
  readonly cleanupImpl?: typeof cleanupWorkspace;
  readonly fetchImpl?: typeof fetch;
  readonly generateId?: () => string;
  readonly now?: () => Date;
  readonly wait?: (ms: number) => Promise<void>;
  readonly webhookRetryAttempts?: number;
  readonly webhookRetryBaseMs?: number;
  readonly random?: () => number;
  readonly licenseStatusProvider?: () => Promise<LicenseStatusResult>;
  readonly licensePublicKey?: string;
  readonly siemDispatcher?: SiemDispatcher;
  readonly ticketingDispatcher?: TicketingDispatcher;
  readonly tracer?: Tracer;
}

function createDatabase(connectionString: string | undefined): Database {
  const PoolClass = Pool as unknown as {
    new (config: { connectionString?: string }): {
      query?: (text: string, values?: unknown[]) => Promise<unknown>;
      connect?: () => Promise<unknown>;
    };
  };

  const rawPool: unknown = new PoolClass({ connectionString });
  if (!rawPool || typeof rawPool !== 'object') {
    throw new Error('Failed to initialize database pool.');
  }

  const candidate = rawPool as { query?: unknown; connect?: unknown };
  if (typeof candidate.query !== 'function') {
    throw new Error('Database pool query function is unavailable.');
  }

  if (typeof candidate.connect !== 'function') {
    throw new Error('Database pool connect function is unavailable.');
  }

  const pool = candidate as {
    query: (text: string, values?: unknown[]) => Promise<unknown>;
    connect: () => Promise<unknown>;
  };

  async function normalizeQueryResult<T>(
    executor: { query: (text: string, values?: unknown[]) => Promise<unknown> },
    text: string,
    values?: ReadonlyArray<unknown>
  ): Promise<{ rows: T[] }> {
    const params = values ? [...values] : [];

    const rawResult = await executor.query(text, params);
    if (!rawResult || typeof rawResult !== 'object' || !('rows' in rawResult)) {
      throw new Error('Database query returned an unexpected result.');
    }

    const rows = (rawResult as { rows: unknown }).rows;
    if (!Array.isArray(rows)) {
      throw new Error('Database query rows must be an array.');
    }

    return { rows: rows as T[] };
  }

  return {
    async query<T>(text: string, values?: ReadonlyArray<unknown>) {
      return normalizeQueryResult<T>(pool, text, values);
    },
    async transaction<T>(handler: (client: DatabaseClient) => Promise<T>) {
      const rawClient = await pool.connect();
      if (!rawClient || typeof rawClient !== 'object') {
        throw new Error('Failed to acquire database connection.');
      }

      const client = rawClient as {
        query?: (text: string, values?: unknown[]) => Promise<unknown>;
        release?: (error?: unknown) => void;
      };

      if (typeof client.query !== 'function') {
        if (typeof client.release === 'function') {
          client.release();
        }
        throw new Error('Database connection query function is unavailable.');
      }

      const release = typeof client.release === 'function' ? client.release.bind(client) : () => {};
      let transactionError: unknown;

      try {
        try {
          await normalizeQueryResult(client as { query: typeof client.query }, 'BEGIN');
        } catch (error) {
          transactionError = error;
          throw error;
        }
        let handlerResult: T;
        try {
        handlerResult = await handler({
          query: (text: string, values?: ReadonlyArray<unknown>) =>
            normalizeQueryResult(client as { query: typeof client.query }, text, values)
        });
        } catch (error) {
          transactionError = error;
          try {
            await normalizeQueryResult(client as { query: typeof client.query }, 'ROLLBACK');
          } catch (rollbackError) {
            transactionError = rollbackError;
            const message = rollbackError instanceof Error ? rollbackError.message : String(rollbackError);
            throw new Error(`Transaction rollback failed: ${message}`, { cause: rollbackError });
          }
          throw error;
        }

        try {
          await normalizeQueryResult(client as { query: typeof client.query }, 'COMMIT');
        } catch (commitError) {
          transactionError = commitError;
          try {
            await normalizeQueryResult(client as { query: typeof client.query }, 'ROLLBACK');
          } catch (rollbackError) {
            transactionError = rollbackError;
            const message = rollbackError instanceof Error ? rollbackError.message : String(rollbackError);
            throw new Error(`Transaction rollback failed: ${message}`, { cause: rollbackError });
          }
          throw commitError;
        }

        return handlerResult;
      } finally {
        release(transactionError instanceof Error ? transactionError : undefined);
      }
    }
  } satisfies Database;
}

export const __testCreateDatabase = createDatabase;
export const __testDeliverWebhook = deliverWebhook;

export async function startWorker(options: WorkerOptions = {}): Promise<BullWorker<ScanJobData>> {
  const config = await loadWorkerConfig(process.env);
  const rawLicensePublicKey = (options.licensePublicKey ?? process.env.LICENSE_PUBLIC_KEY ?? '').trim();
  const resolvedLicenseKey = rawLicensePublicKey.startsWith(SECRETS_MANAGER_PREFIX)
    ? await resolveWorkerSecret(rawLicensePublicKey, 'LICENSE_PUBLIC_KEY')
    : rawLicensePublicKey;
  const licensePublicKey = resolvedLicenseKey
    ? validateLicensePublicKey(resolvedLicenseKey, 'LICENSE_PUBLIC_KEY')
    : resolvedLicenseKey;
  const licenseStatusProvider =
    options.licenseStatusProvider ??
    (() =>
      getLicenseStatus({
        logger: (message: string) => {
          console.info(`[worker-license] ${message}`);
        },
        ...(licensePublicKey ? { publicKey: licensePublicKey } : {})
      }));

  const licenseStatus = await licenseStatusProvider().catch((error: unknown) => {
    console.error('Worker license validation failed.', error);
    throw new Error('Worker requires an active license with scan:execute entitlement.');
  });

  if (licenseStatus.status !== 'active') {
    console.error(
      'Worker license is not active.',
      JSON.stringify({ licenseId: licenseStatus.licenseId, status: licenseStatus.status, warnings: licenseStatus.warnings })
    );
    throw new Error(`License ${licenseStatus.licenseId} is ${licenseStatus.status}; refusing to start worker.`);
  }

  if (!licenseStatus.features.includes(REQUIRED_SCAN_FEATURE)) {
    console.error(
      'Worker license missing scan entitlement.',
      JSON.stringify({ licenseId: licenseStatus.licenseId, features: licenseStatus.features })
    );
    throw new Error(
      `License ${licenseStatus.licenseId} is missing required feature ${REQUIRED_SCAN_FEATURE}; refusing to start worker.`
    );
  }

  const queueName = options.queueName ?? config.scanQueueName;
  const connection = options.connection ?? getRedisConnection(config);
  const db = options.db ?? createDatabase(config.databaseUrl);
  const metrics = options.metrics ?? defaultMetrics;
  const tracer =
    options.tracer ?? createTracer('atlas-sca-worker', { enabled: config.telemetryEnabled === true });

  const dependencies: WorkerDependencies = {
    db,
    fetchArtifact: options.fetchArtifactImpl ?? fetchArtifact,
    runScanners: options.runScannersImpl ?? runScanners,
    cleanupWorkspace: options.cleanupImpl ?? cleanupWorkspace,
    metrics,
    fetchImpl: options.fetchImpl ?? fetch,
    generateId: options.generateId ?? randomUUID,
    now: options.now ?? (() => new Date()),
    wait: options.wait ?? defaultWait,
    webhookRetryAttempts: options.webhookRetryAttempts ?? DEFAULT_WEBHOOK_ATTEMPTS,
    webhookRetryBaseMs: options.webhookRetryBaseMs ?? WEBHOOK_RETRY_BASE_MS,
    webhookSecretKey: config.webhookSecretKey,
    random: options.random ?? Math.random,
    sendSiemEvent: options.siemDispatcher
      ? (event) => options.siemDispatcher!.publish(event)
      : undefined,
    syncTicketing: options.ticketingDispatcher
      ? (event) => options.ticketingDispatcher!.sync(event)
      : undefined,
    tracer
  };

  const worker = new BullWorker<ScanJobData>(
    queueName,
    async (job: Job<ScanJobData>) => {
      await processScanJob(job.data, dependencies);
    },
    { connection }
  );

  worker.on('completed', (job) => {
    console.log(`Scan job ${job.id} completed`);
  });

  worker.on('failed', (job, err) => {
    console.error(`Scan job ${job?.id} failed`, err);
  });

  return worker;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await startWorker();
}
