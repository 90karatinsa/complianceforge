// SPDX-License-Identifier: MIT

import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { mockPgModule, resetPools, setNextQueryImplementation } from './pg-mock.ts';

vi.mock('pg', () => mockPgModule());

async function createMigrationFile(dir: string, name: string, content: string): Promise<void> {
  const filePath = path.join(dir, name);
  await writeFile(filePath, content, 'utf8');
}

describe('runMigrations', () => {
  beforeEach(() => {
    resetPools();
    setNextQueryImplementation(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('executes migrations in order when not in dry-run mode', async () => {
    const { runMigrations } = await import('../../scripts/migrate.ts');
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'migrate-'));
    await createMigrationFile(tempDir, '001_init.sql', 'CREATE TABLE example(id INT);');
    await createMigrationFile(tempDir, '002_extra.sql', "INSERT INTO example(id) VALUES (1);\n");

    await runMigrations({
      dryRun: false,
      databaseUrl: 'postgres://example',
      migrationsDir: tempDir,
      logger: () => {}
    });

    const pools = resetPools();
    expect(pools).toHaveLength(1);
    const [pool] = pools;
    expect(pool).toBeDefined();
    if (!pool) {
      throw new Error('Expected a mocked pool to be created');
    }

    expect(pool.__config).toEqual({ connectionString: 'postgres://example' });
    const executedStatements = pool.__query.mock.calls.map(([sql]) => {
      if (typeof sql !== 'string') {
        throw new Error('Expected first argument of query call to be SQL string');
      }
      return sql;
    });
    expect(executedStatements).toEqual([
      'BEGIN',
      'CREATE TABLE example(id INT);',
      'INSERT INTO example(id) VALUES (1);',
      'COMMIT'
    ]);
    expect(pool.connect).toHaveBeenCalledTimes(1);
    expect(pool.end).toHaveBeenCalledTimes(1);
  });

  it('prints statements with DRY RUN prefix when dry-run is enabled', async () => {
    const { runMigrations } = await import('../../scripts/migrate.ts');
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'migrate-'));
    await createMigrationFile(tempDir, '001_init.sql', 'CREATE TABLE t(a TEXT);');
    const logs: string[] = [];

    await runMigrations({
      dryRun: true,
      migrationsDir: tempDir,
      logger: (message) => logs.push(message)
    });

    expect(logs).toEqual(['DRY RUN: 001_init.sql [1/1] CREATE TABLE t(a TEXT);']);
  });

  it('throws when DATABASE_URL is missing in non dry-run mode', async () => {
    const { runMigrations } = await import('../../scripts/migrate.ts');
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'migrate-'));
    await createMigrationFile(tempDir, '001_init.sql', 'CREATE TABLE missing(id INT);');

    await expect(
      runMigrations({
        dryRun: false,
        migrationsDir: tempDir,
        logger: () => {}
      })
    ).rejects.toThrow('DATABASE_URL must be provided');
  });

  it('propagates query errors and still releases client', async () => {
    const { runMigrations } = await import('../../scripts/migrate.ts');
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'migrate-'));
    await createMigrationFile(tempDir, '001_init.sql', 'CREATE TABLE broken(id INT);');

    const error = new Error('boom');
    setNextQueryImplementation(() => Promise.reject(error));

    await expect(
      runMigrations({
        dryRun: false,
        databaseUrl: 'postgres://example',
        migrationsDir: tempDir,
        logger: () => {}
      })
    ).rejects.toThrow('boom');

    const pools = resetPools();
    const [pool] = pools;
    expect(pool).toBeDefined();
    if (!pool) {
      throw new Error('Expected a mocked pool to be created');
    }
    expect(pool.__query).toHaveBeenCalled();
    expect(pool.end).toHaveBeenCalledTimes(1);
  });
});
