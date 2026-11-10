// SPDX-License-Identifier: MIT

import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';

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

type PgPoolShape = DatabasePool;

function isPgPool(value: unknown): value is PgPoolShape {
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

const DEFAULT_MIGRATIONS_DIR = path.resolve(process.cwd(), 'schemas', 'migrations');
const DRY_RUN_PREFIX = 'DRY RUN';

interface MigrationOptions {
  readonly dryRun: boolean;
  readonly databaseUrl?: string;
  readonly migrationsDir?: string;
  readonly logger?: (message: string) => void;
}

interface CliArguments {
  readonly dryRun: boolean;
  readonly databaseUrl?: string;
  readonly migrationsDir?: string;
}

interface MigrationFile {
  readonly filename: string;
  readonly statements: readonly string[];
}

function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let dollarTag: string | null = null;

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const nextTwo = sql.slice(i, i + 2);

    if (dollarTag !== null) {
      if (char === '$' && sql.startsWith(dollarTag, i)) {
        current += dollarTag;
        i += dollarTag.length - 1;
        dollarTag = null;
        continue;
      }
      current += char;
      continue;
    }

    if (inSingleQuote) {
      current += char;
      if (char === "'" && sql[i - 1] !== '\\') {
        inSingleQuote = false;
      }
      continue;
    }

    if (inDoubleQuote) {
      current += char;
      if (char === '"' && sql[i - 1] !== '\\') {
        inDoubleQuote = false;
      }
      continue;
    }

    if (char === '$') {
      const match = /\$[A-Za-z0-9_]*\$/.exec(sql.slice(i));
      if (match && match.index === 0) {
        const tag = match[0];
        dollarTag = tag;
        current += tag;
        i += tag.length - 1;
        continue;
      }
    }

    if (char === "'") {
      inSingleQuote = true;
      current += char;
      continue;
    }

    if (char === '"') {
      inDoubleQuote = true;
      current += char;
      continue;
    }

    if (nextTwo === '--') {
      const newlineIndex = sql.indexOf('\n', i);
      if (newlineIndex === -1) {
        break;
      }
      current += sql.slice(i, newlineIndex + 1);
      i = newlineIndex;
      continue;
    }

    if (char === ';') {
      const trimmed = current.trim();
      if (trimmed.length > 0) {
        statements.push(trimmed + ';');
      }
      current = '';
      continue;
    }

    current += char;
  }

  const tail = current.trim();
  if (tail.length > 0) {
    statements.push(tail);
  }

  return statements;
}

async function loadMigrationFiles(migrationsDir: string): Promise<MigrationFile[]> {
  const entries = await readdir(migrationsDir);
  const sqlFiles = entries.filter((filename) => filename.endsWith('.sql')).sort();
  const migrations: MigrationFile[] = [];

  for (const filename of sqlFiles) {
    const absolutePath = path.join(migrationsDir, filename);
    const content = await readFile(absolutePath, 'utf8');
    const statements = splitSqlStatements(content);
    migrations.push({ filename, statements });
  }

  return migrations;
}

async function executeStatements(client: DatabaseClient, file: MigrationFile, logger: (message: string) => void): Promise<void> {
  for (const [index, statement] of file.statements.entries()) {
    logger(`Running ${file.filename} [${index + 1}/${file.statements.length}]`);
    // eslint-disable-next-line no-await-in-loop
    await client.query(statement);
  }
}

export async function runMigrations({
  dryRun,
  databaseUrl,
  migrationsDir = DEFAULT_MIGRATIONS_DIR,
  logger = (message) => {
    process.stdout.write(`${message}\n`);
  }
}: MigrationOptions): Promise<void> {
  const files = await loadMigrationFiles(migrationsDir);
  if (files.length === 0) {
    logger('No migrations to execute.');
    return;
  }

  if (dryRun) {
    for (const file of files) {
      file.statements.forEach((statement, index) => {
        logger(`${DRY_RUN_PREFIX}: ${file.filename} [${index + 1}/${file.statements.length}] ${statement}`);
      });
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

  const pool: PgPoolShape = rawPool;
  let client: DatabaseClient | undefined;

  try {
    const rawClient: unknown = await pool.connect();
    if (!isPgClient(rawClient)) {
      throw new Error('Failed to acquire PostgreSQL client.');
    }

    client = rawClient;
    await client.query('BEGIN');
    for (const file of files) {
      await executeStatements(client, file, logger);
    }
    await client.query('COMMIT');
  } catch (error) {
    if (client) {
      try {
        await client.query('ROLLBACK');
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

function parseCliArguments(args: readonly string[]): CliArguments {
  let dryRun = false;
  let url: string | undefined;
  let dir: string | undefined;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--url') {
      url = args[i + 1];
      i += 1;
    } else if (arg === '--dir') {
      dir = args[i + 1];
      i += 1;
    }
  }

  return {
    dryRun,
    databaseUrl: url,
    migrationsDir: dir ? path.resolve(process.cwd(), dir) : undefined
  };
}

async function cli(): Promise<void> {
  const options = parseCliArguments(process.argv.slice(2));
  await runMigrations({
    dryRun: options.dryRun,
    databaseUrl: options.databaseUrl,
    migrationsDir: options.migrationsDir,
    logger: (message) => {
      process.stdout.write(`${message}\n`);
    }
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
    process.stderr.write(`Migration failed: ${failure.message}\n`);
    process.exitCode = 1;
  });
}

export { splitSqlStatements };
