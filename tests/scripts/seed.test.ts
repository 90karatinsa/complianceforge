// SPDX-License-Identifier: MIT

import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { mockPgModule, resetPools, setNextQueryImplementation } from './pg-mock.ts';

vi.mock('pg', () => mockPgModule());

describe('runSeed', () => {
  beforeEach(() => {
    resetPools();
    setNextQueryImplementation(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('executes seed statements sequentially when not dry-run', async () => {
    const { runSeed } = await import('../../scripts/seed.ts');
    const logs: string[] = [];

    await runSeed({
      dryRun: false,
      databaseUrl: 'postgres://seed',
      logger: (message) => logs.push(message),
      apiKeySalt: 'seed-salt',
      demoApiToken: 'seed-demo-token'
    });

    const pools = resetPools();
    expect(pools).toHaveLength(1);
    const pool = pools[0];
    expect(pool).toBeDefined();
    if (!pool) {
      throw new Error('Expected pool to be defined');
    }

    expect(pool.__config).toEqual({ connectionString: 'postgres://seed' });
    const queryCalls: readonly unknown[][] = pool.__query.mock.calls;
    const firstStatements = queryCalls.map((call) => {
      const [sql] = call;
      if (typeof sql !== 'string') {
        throw new Error('Expected SQL string in query call');
      }
      return sql.trim().split('\n')[0];
    });
    expect(firstStatements).toEqual([
      'BEGIN;',
      "INSERT INTO tenants (id, name, slug, metadata)",
      "INSERT INTO api_keys (id, tenant_id, name, token_hash, token_lookup_hash, permissions)",
      "INSERT INTO projects (id, tenant_id, name, description, repo_url, oci_ref, metadata)",
      "INSERT INTO policies (id, tenant_id, name, description, rules)",
      "INSERT INTO artifacts (id, project_id, type, ref, metadata)",
      "INSERT INTO scans (id, project_id, artifact_id, policy_id, policy_result, status, findings, duration_ms, started_at, completed_at)",
      "INSERT INTO sboms (id, project_id, artifact_id, scan_id, format, bom, component_count)",
      "INSERT INTO licenses (id, sbom_id, component_purl, detected_spdx_id, evidence)",
      "INSERT INTO vulns (id, scan_id, component_purl, source, cve_id, severity, cvss, summary, fixed_version)",
      'COMMIT;'
    ]);
    const expectedHash = createHash('sha256')
      .update('seed-salt:seed-demo-token')
      .digest('hex');
    const insertCalls = queryCalls.filter((call) => {
      const [sql] = call;
      return typeof sql === 'string' && sql.startsWith('INSERT INTO api_keys');
    });
    expect(insertCalls).toHaveLength(1);
    const [apiKeyCall] = insertCalls;
    const [apiKeySql] = apiKeyCall;
    if (typeof apiKeySql !== 'string') {
      throw new Error('Expected API key insert SQL to be a string');
    }
    expect(apiKeySql).toContain(expectedHash);
    expect(apiKeySql).toMatch(/\$argon2id\$/);
    expect(pool.end).toHaveBeenCalledTimes(1);
    expect(logs).toHaveLength(0);
  });

  it('prints dry-run output with DRY RUN prefix', async () => {
    const { runSeed } = await import('../../scripts/seed.ts');
    const output: string[] = [];
    await runSeed({
      dryRun: true,
      logger: (message) => output.push(message),
      apiKeySalt: 'seed-salt'
    });

    expect(output[0]).toContain('DRY RUN: [1/');
    expect(output[0]).toContain('BEGIN;');
    expect(output.at(-1)).toContain('COMMIT;');
  });

  it('throws when DATABASE_URL is missing', async () => {
    const { runSeed } = await import('../../scripts/seed.ts');
    await expect(
      runSeed({
        dryRun: false,
        logger: () => {},
        apiKeySalt: 'seed-salt'
      })
    ).rejects.toThrow('DATABASE_URL must be provided');
  });

  it('throws when API key salt is missing', async () => {
    const { runSeed } = await import('../../scripts/seed.ts');
    await expect(
      runSeed({
        dryRun: true,
        logger: () => {}
      })
    ).rejects.toThrow('API_KEYS_SALT must be provided to seed demo credentials.');
  });

  it('rolls back on failure and still releases resources', async () => {
    const { runSeed } = await import('../../scripts/seed.ts');
    const error = new Error('seed failure');
    setNextQueryImplementation((sql: string) => {
      if (sql.startsWith('INSERT INTO projects')) {
        return Promise.reject(error);
      }
      return Promise.resolve(undefined);
    });

    await expect(
      runSeed({
        dryRun: false,
        databaseUrl: 'postgres://seed',
        logger: () => {},
        apiKeySalt: 'seed-salt'
      })
    ).rejects.toThrow('seed failure');

    const pools = resetPools();
    const pool = pools[0];
    expect(pool).toBeDefined();
    if (!pool) {
      throw new Error('Expected pool to be defined');
    }

    expect(pool.__query).toHaveBeenCalledWith('ROLLBACK;');
    expect(pool.end).toHaveBeenCalledTimes(1);
  });
});
