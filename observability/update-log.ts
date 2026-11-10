// SPDX-License-Identifier: MIT

import { appendFile, chmod, lstat, mkdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

type UpdateResult = 'success' | 'failure' | 'blocked';

const LOG_DIRECTORY = ['.config', 'otomatik-oss'];
const LOG_FILENAME = 'updates.log';
const LOG_MAX_BYTES = 5 * 1024 * 1024;
const LOG_MAX_BACKUPS = 2;

interface UpdateLogDependencies {
  readonly now: () => Date;
  readonly mkdir: typeof mkdir;
  readonly appendFile: typeof appendFile;
  readonly rename: typeof rename;
  readonly rm: typeof rm;
  readonly chmod: typeof chmod;
  readonly lstat: typeof lstat;
  readonly stat: typeof stat;
  readonly writeFile: typeof writeFile;
  readonly homedir: typeof os.homedir;
  readonly platform: () => NodeJS.Platform;
}

export interface UpdateLogEntry {
  readonly action: string;
  readonly manifest_id: string | null;
  readonly version: string | null;
  readonly actor: string;
  readonly result: UpdateResult;
  readonly metadata?: Record<string, unknown>;
}

interface RecordUpdateLogOptions {
  readonly dependencies?: Partial<UpdateLogDependencies>;
}

function resolveDependencies(overrides?: Partial<UpdateLogDependencies>): UpdateLogDependencies {
  return {
    now: overrides?.now ?? (() => new Date()),
    mkdir: overrides?.mkdir ?? mkdir,
    appendFile: overrides?.appendFile ?? appendFile,
    rename: overrides?.rename ?? rename,
    chmod: overrides?.chmod ?? chmod,
    rm: overrides?.rm ?? rm,
    lstat: overrides?.lstat ?? lstat,
    stat: overrides?.stat ?? stat,
    writeFile: overrides?.writeFile ?? writeFile,
    homedir: overrides?.homedir ?? os.homedir,
    platform: overrides?.platform ?? (() => process.platform)
  };
}

const SENSITIVE_KEY_TOKENS = [
  'api_key',
  'apikey',
  'api-key',
  'secret',
  'password',
  'token',
  'credential'
] as const;

function normalizeKeyFragment(value: string): string {
  return value.toLowerCase();
}

function collapseKey(value: string): string {
  return normalizeKeyFragment(value).replace(/[^a-z0-9]+/gu, '_');
}

function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKeyFragment(key);
  const collapsed = collapseKey(key);

  return SENSITIVE_KEY_TOKENS.some((token) => {
    const normalizedToken = normalizeKeyFragment(token);
    const collapsedToken = collapseKey(token);

    return (
      normalized === normalizedToken ||
      collapsed === collapsedToken ||
      collapsed.startsWith(`${collapsedToken}_`) ||
      collapsed.endsWith(`_${collapsedToken}`) ||
      collapsed.startsWith(collapsedToken) ||
      collapsed.endsWith(collapsedToken)
    );
  });
}

function sanitizeMetadata(value: unknown): unknown {
  if (value == null) {
    return value as null | undefined;
  }

  if (typeof value === 'string') {
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeMetadata(entry));
  }

  if (typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};

    for (const [key, entry] of Object.entries(source)) {
      if (isSensitiveKey(key)) {
        output[key] = '***';
        continue;
      }

      output[key] = sanitizeMetadata(entry);
    }

    return output;
  }

  return String(value);
}

function resolveLogDirectory(deps: UpdateLogDependencies): string {
  return path.join(deps.homedir(), ...LOG_DIRECTORY);
}

async function ensureLogDirectory(deps: UpdateLogDependencies): Promise<string> {
  const directory = resolveLogDirectory(deps);
  await deps.mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    const stats = await deps.lstat(directory);

    if (typeof stats.isSymbolicLink === 'function' && stats.isSymbolicLink()) {
      throw new Error('Update log directory must not be a symbolic link.');
    }

    if (typeof stats.isDirectory === 'function' && !stats.isDirectory()) {
      throw new Error('Update log path must resolve to a directory.');
    }

    const permissions = stats.mode & 0o777;

    if ((permissions & 0o077) !== 0 || permissions !== 0o700) {
      await deps.chmod(directory, 0o700);
      const updated = await deps.lstat(directory);
      const updatedPermissions = updated.mode & 0o777;

      if ((updatedPermissions & 0o077) !== 0 || updatedPermissions !== 0o700) {
        throw new Error('Update log directory permissions must be owner-only (0700).');
      }
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    if (code !== 'ENOENT') {
      throw error;
    }
  }
  return directory;
}

async function assertWritableLogTarget(
  deps: UpdateLogDependencies,
  logPath: string
): Promise<void> {
  try {
    const stats = await deps.lstat(logPath);

    if (typeof stats.isSymbolicLink === 'function' && stats.isSymbolicLink()) {
      throw new Error('Update log file must not be a symlink.');
    }

    if (typeof stats.isFile === 'function' && !stats.isFile()) {
      throw new Error('Update log target must be a regular file.');
    }

    if (deps.platform() !== 'win32') {
      const permissions = stats.mode & 0o777;

      if (permissions !== 0o600) {
        await deps.chmod(logPath, 0o600);
        const updated = await deps.lstat(logPath);
        const updatedPermissions = updated.mode & 0o777;

        if (updatedPermissions !== 0o600) {
          throw new Error('Update log file permissions must be owner read/write only (0600).');
        }
      }
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') {
      return;
    }
    throw error;
  }
}

async function rotateLogsIfNeeded(deps: UpdateLogDependencies, logPath: string): Promise<void> {
  try {
    const stats = await deps.stat(logPath);
    if (stats.size < LOG_MAX_BYTES) {
      return;
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') {
      return;
    }
    throw error;
  }

  await assertWritableLogTarget(deps, logPath);

  for (let index = LOG_MAX_BACKUPS; index >= 1; index -= 1) {
    const source = index === 1 ? logPath : `${logPath}.${index - 1}`;
    const target = `${logPath}.${index}`;

    try {
      await deps.rm(target, { force: true });
    } catch (error) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT') {
        throw error;
      }
    }

    try {
      await deps.rename(source, target);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT') {
        throw error;
      }
    }
  }

  await deps.writeFile(logPath, '', { encoding: 'utf8', mode: 0o600 });
}

export async function recordUpdateLogEntry(
  entry: UpdateLogEntry,
  options?: RecordUpdateLogOptions
): Promise<void> {
  const deps = resolveDependencies(options?.dependencies);
  const directory = await ensureLogDirectory(deps);
  const logPath = path.join(directory, LOG_FILENAME);
  await rotateLogsIfNeeded(deps, logPath);
  await assertWritableLogTarget(deps, logPath);

  const record: Record<string, unknown> = {
    timestamp: deps.now().toISOString(),
    action: entry.action,
    manifest_id: entry.manifest_id ?? null,
    version: entry.version ?? null,
    actor: entry.actor ?? 'unknown',
    result: entry.result
  };

  if (entry.metadata && Object.keys(entry.metadata).length > 0) {
    record.metadata = sanitizeMetadata(entry.metadata) as Record<string, unknown>;
  }

  await deps.appendFile(logPath, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
}
