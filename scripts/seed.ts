// SPDX-License-Identifier: MIT

import { createHash } from 'node:crypto';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import argon2 from 'argon2';

type UnknownRecord = Record<PropertyKey, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null;
}

interface DatabaseClient {
  query: (sql: string) => Promise<unknown>;
  release: () => void;
}

interface DatabasePool {
  connect: () => Promise<DatabaseClient>;
  end: () => Promise<void>;
  query: (sql: string) => Promise<unknown>;
}

function isPgPool(value: unknown): value is DatabasePool {
  if (!isRecord(value)) {
    return false;
  }

  const connect = value.connect;
  const end = value.end;
  const query = value.query;

  return (
    typeof connect === 'function' &&
    typeof end === 'function' &&
    typeof query === 'function'
  );
}

function isPgClient(value: unknown): value is DatabaseClient {
  if (!isRecord(value)) {
    return false;
  }

  const query = value.query;
  const release = value.release;

  return typeof query === 'function' && typeof release === 'function';
}

function normalizeError(error: unknown): Error {
  if (error instanceof Error) {
    return error;
  }

  if (typeof error === 'string') {
    return new Error(error);
  }

  try {
    return new Error(JSON.stringify(error));
  } catch {
    return new Error('Unknown error');
  }
}

const DRY_RUN_PREFIX = 'DRY RUN';

interface SeedOptions {
  readonly dryRun: boolean;
  readonly databaseUrl?: string;
  readonly logger?: (message: string) => void;
  readonly apiKeySalt?: string;
  readonly demoApiToken?: string;
}

interface CliArguments {
  readonly dryRun: boolean;
  readonly databaseUrl?: string;
}

const TENANT_ID = '00000000-0000-0000-0000-000000000001';
const API_KEY_ID = '00000000-0000-0000-0000-000000000101';
const PROJECT_ID = '00000000-0000-0000-0000-000000000201';
const POLICY_ID = '00000000-0000-0000-0000-000000000301';
const ARTIFACT_ID = '00000000-0000-0000-0000-000000000401';
const SCAN_ID = '00000000-0000-0000-0000-000000000501';
const SBOM_ID = '00000000-0000-0000-0000-000000000601';
const LICENSE_ID = '00000000-0000-0000-0000-000000000701';
const VULN_ID = '00000000-0000-0000-0000-000000000801';
const DEFAULT_DEMO_API_TOKEN = 'alterra-demo-api-token';

interface SeedConfiguration {
  readonly demoApiToken: string;
  readonly tokenLookupHash: string;
  readonly tokenDigest: string;
}

const ARGON2_OPTIONS: argon2.Options & { type: argon2.Type } = {
  type: argon2.argon2id,
  memoryCost: 15_360,
  timeCost: 2,
  parallelism: 1
};

function buildStatements(configuration: SeedConfiguration): string[] {
  return [
    'BEGIN;',
    `INSERT INTO tenants (id, name, slug, metadata)
VALUES ('${TENANT_ID}', 'Acme Demo Tenant', 'acme-demo', '{}'::jsonb)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, slug = EXCLUDED.slug, metadata = EXCLUDED.metadata;`,
    `INSERT INTO api_keys (id, tenant_id, name, token_hash, token_lookup_hash, permissions)
VALUES ('${API_KEY_ID}', '${TENANT_ID}', 'Demo Key', '${configuration.tokenDigest}', '${configuration.tokenLookupHash}', '["scan:read","scan:write"]'::jsonb)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, token_hash = EXCLUDED.token_hash, token_lookup_hash = EXCLUDED.token_lookup_hash, permissions = EXCLUDED.permissions;`,
    `INSERT INTO projects (id, tenant_id, name, description, repo_url, oci_ref, metadata)
VALUES ('${PROJECT_ID}', '${TENANT_ID}', 'Demo Project', 'Example project for onboarding', 'https://example.com/repo.git', 'registry.example.com/demo:latest', '{"language":"node"}'::jsonb)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, repo_url = EXCLUDED.repo_url, oci_ref = EXCLUDED.oci_ref, metadata = EXCLUDED.metadata;`,
    `INSERT INTO policies (id, tenant_id, name, description, rules)
VALUES ('${POLICY_ID}', '${TENANT_ID}', 'Default Policy', 'Baseline policy for demo tenant', '{"allowed_spdx":["MIT","Apache-2.0"],"denied_spdx":["GPL-3.0-only"],"cvss_threshold":7.0}'::jsonb)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, rules = EXCLUDED.rules;`,
    `INSERT INTO artifacts (id, project_id, type, ref, metadata)
VALUES ('${ARTIFACT_ID}', '${PROJECT_ID}', 'git', '{"branch":"main","commit":"demo123"}'::jsonb, '{}'::jsonb)
ON CONFLICT (id) DO UPDATE SET type = EXCLUDED.type, ref = EXCLUDED.ref, metadata = EXCLUDED.metadata;`,
    `INSERT INTO scans (id, project_id, artifact_id, policy_id, policy_result, status, findings, duration_ms, started_at, completed_at)
VALUES ('${SCAN_ID}', '${PROJECT_ID}', '${ARTIFACT_ID}', '${POLICY_ID}', 'pass', 'succeeded', '{}'::jsonb, 12345, NOW() - INTERVAL '5 minutes', NOW())
ON CONFLICT (id) DO UPDATE SET policy_result = EXCLUDED.policy_result, status = EXCLUDED.status, findings = EXCLUDED.findings, duration_ms = EXCLUDED.duration_ms, started_at = EXCLUDED.started_at, completed_at = EXCLUDED.completed_at;`,
    `INSERT INTO sboms (id, project_id, artifact_id, scan_id, format, bom, component_count)
VALUES ('${SBOM_ID}', '${PROJECT_ID}', '${ARTIFACT_ID}', '${SCAN_ID}', 'cyclonedx', '{"components":[{"name":"demo","version":"1.0.0"}]}'::jsonb, 1)
ON CONFLICT (id) DO UPDATE SET format = EXCLUDED.format, bom = EXCLUDED.bom, component_count = EXCLUDED.component_count;`,
    `INSERT INTO licenses (id, sbom_id, component_purl, detected_spdx_id, evidence)
VALUES ('${LICENSE_ID}', '${SBOM_ID}', 'pkg:npm/demo@1.0.0', 'MIT', '{"confidence":1.0}'::jsonb)
ON CONFLICT (id) DO UPDATE SET component_purl = EXCLUDED.component_purl, detected_spdx_id = EXCLUDED.detected_spdx_id, evidence = EXCLUDED.evidence;`,
    `INSERT INTO vulns (id, scan_id, component_purl, source, cve_id, severity, cvss, summary, fixed_version)
VALUES ('${VULN_ID}', '${SCAN_ID}', 'pkg:npm/demo@1.0.0', 'osv', 'CVE-2024-0001', 'medium', 5.5, 'Demonstration vulnerability entry', '1.0.1')
ON CONFLICT (id) DO UPDATE SET component_purl = EXCLUDED.component_purl, source = EXCLUDED.source, cve_id = EXCLUDED.cve_id, severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, summary = EXCLUDED.summary, fixed_version = EXCLUDED.fixed_version;`,
    'COMMIT;'
  ];
}

export async function runSeed(options: SeedOptions): Promise<void> {
  const { dryRun, databaseUrl, logger = (message) => process.stdout.write(`${message}\n`) } = options;
  const configuration = await resolveSeedConfiguration(options);
  const statements = buildStatements(configuration);

  if (dryRun) {
    for (const [index, statement] of statements.entries()) {
      logger(`${DRY_RUN_PREFIX}: [${index + 1}/${statements.length}] ${statement}`);
    }
    return;
  }

  const connectionString = databaseUrl ?? process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL must be provided when not running in dry-run mode.');
  }

  const rawPool: unknown = new Pool({ connectionString });
  if (!isPgPool(rawPool)) {
    throw new Error('Failed to initialize PostgreSQL pool.');
  }

  const pool: DatabasePool = rawPool;
  let client: DatabaseClient | undefined;

  try {
    const rawClient: unknown = await pool.connect();
    if (!isPgClient(rawClient)) {
      throw new Error('Failed to acquire PostgreSQL client.');
    }

    client = rawClient;
    for (const statement of statements) {
      // eslint-disable-next-line no-await-in-loop
      await client.query(statement);
    }
  } catch (error) {
    if (client) {
      try {
        await client.query('ROLLBACK;');
      } catch (rollbackError) {
        logger(`Rollback failed: ${normalizeError(rollbackError).message}`);
      }
    }
    throw normalizeError(error);
  } finally {
    if (client) {
      client.release();
    }
    await pool.end();
  }
}

async function resolveSeedConfiguration(options: SeedOptions): Promise<SeedConfiguration> {
  const salt = options.apiKeySalt ?? process.env.API_KEYS_SALT;
  if (!salt) {
    throw new Error('API_KEYS_SALT must be provided to seed demo credentials.');
  }

  const demoApiToken = options.demoApiToken ?? process.env.DEMO_API_TOKEN ?? DEFAULT_DEMO_API_TOKEN;
  const tokenLookupHash = createHash('sha256').update(`${salt}:${demoApiToken}`).digest('hex');
  const tokenDigest = await argon2.hash(tokenLookupHash, ARGON2_OPTIONS);

  return {
    demoApiToken,
    tokenLookupHash,
    tokenDigest
  };
}

function parseCliArguments(args: readonly string[]): CliArguments {
  let dryRun = false;
  let url: string | undefined;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--url') {
      url = args[i + 1];
      i += 1;
    }
  }

  return {
    dryRun,
    databaseUrl: url
  };
}

async function cli(): Promise<void> {
  const options = parseCliArguments(process.argv.slice(2));
  await runSeed({
    dryRun: options.dryRun,
    databaseUrl: options.databaseUrl,
    logger: (message) => process.stdout.write(`${message}\n`)
  });
}

function isExecutedDirectly(): boolean {
  const entryPoint = process.argv[1];
  if (!entryPoint) {
    return false;
  }
  return import.meta.url === pathToFileURL(entryPoint).href;
}

if (isExecutedDirectly()) {
  cli().catch((error: unknown) => {
    const failure = error instanceof Error ? error : new Error(String(error));
    process.stderr.write(`Seed failed: ${failure.message}\n`);
    process.exitCode = 1;
  });
}
