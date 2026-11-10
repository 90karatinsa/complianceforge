// SPDX-License-Identifier: MIT

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import * as fs from 'node:fs/promises';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Agent } from 'undici';

import { assertNetworkFetchAllowed } from './network-guard.js';

const EXEC_TIMEOUT_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 30_000;
const MAX_ARCHIVE_SIZE = 200 * 1024 * 1024;
const WORKSPACE_PREFIX = 'otomatik-workspaces';
const ARTIFACT_CIRCUIT_FAILURE_THRESHOLD = 3;
const ARTIFACT_CIRCUIT_COOLDOWN_MS = 60_000;

const GIT_BIN_ENV = 'GIT_BIN';
const TAR_BIN_ENV = 'TAR_BIN';
const UNZIP_BIN_ENV = 'UNZIP_BIN';

type ArchiveType = 'zip' | 'tar';

export interface PrivateAddressError extends Error {
  code?: string;
}

type UndiciAgentInstance = InstanceType<typeof Agent>;
type GuardedDispatcher = Pick<UndiciAgentInstance, 'dispatch' | 'close' | 'destroy'>;
type FetchRequestOptions = NonNullable<Parameters<typeof fetch>[1]> & {
  readonly dispatcher: GuardedDispatcher;
};
type FetchResponse = Awaited<ReturnType<typeof fetch>>;

type StreamReader = {
  read(): Promise<{ value?: Uint8Array; done: boolean }>;
  cancel(reason?: unknown): Promise<void>;
};

type WebStreamLike = {
  getReader?: () => StreamReader;
};

type TimeoutGuard = {
  readonly controller: AbortController;
  reset(): void;
  clear(): void;
};

type DispatcherCloseFn = (this: GuardedDispatcher) => Promise<void>;
type DispatcherDestroyFn = (this: GuardedDispatcher, error?: Error) => void | Promise<void>;

type CircuitState = {
  failures: number;
  state: 'closed' | 'open' | 'half-open';
  openedAt: number;
  trialInProgress: boolean;
};

const artifactCircuitStates = new Map<string, CircuitState>();

function circuitKeyFromHost(host: string): string {
  return host.toLowerCase();
}

function allowArtifactAttempt(hostKey: string, nowMs: number): boolean {
  const state = artifactCircuitStates.get(hostKey);

  if (!state) {
    return true;
  }

  if (state.state === 'open') {
    if (nowMs - state.openedAt >= ARTIFACT_CIRCUIT_COOLDOWN_MS) {
      state.state = 'half-open';
      state.trialInProgress = false;
      artifactCircuitStates.set(hostKey, state);
    } else {
      return false;
    }
  }

  if (state.state === 'half-open') {
    if (state.trialInProgress) {
      return false;
    }

    state.trialInProgress = true;
    artifactCircuitStates.set(hostKey, state);
    return true;
  }

  return true;
}

function recordArtifactFailure(hostKey: string, nowMs: number): boolean {
  const existing = artifactCircuitStates.get(hostKey);

  if (!existing) {
    artifactCircuitStates.set(hostKey, {
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
    existing.failures = ARTIFACT_CIRCUIT_FAILURE_THRESHOLD;
    existing.trialInProgress = false;
    artifactCircuitStates.set(hostKey, existing);
    return true;
  }

  if (existing.state === 'open') {
    existing.openedAt = nowMs;
    artifactCircuitStates.set(hostKey, existing);
    return true;
  }

  existing.failures += 1;

  if (existing.failures >= ARTIFACT_CIRCUIT_FAILURE_THRESHOLD) {
    existing.state = 'open';
    existing.openedAt = nowMs;
    existing.trialInProgress = false;
    artifactCircuitStates.set(hostKey, existing);
    return true;
  }

  artifactCircuitStates.set(hostKey, existing);
  return false;
}

function recordArtifactSuccess(hostKey: string): void {
  artifactCircuitStates.delete(hostKey);
}

interface ArchiveEntry {
  readonly name: string;
  readonly type: 'file' | 'directory' | 'symlink' | 'other';
  readonly linkTarget?: string;
}

export interface ArtifactDefinition {
  readonly type: 'git' | 'archive' | 'oci';
  readonly ref: Record<string, unknown>;
  readonly metadata?: Record<string, unknown>;
}

export interface FetchOptions {
  readonly scanId: string;
  readonly artifact: ArtifactDefinition;
  readonly workspaceRoot?: string;
  readonly fetchImpl?: typeof fetch;
}

export interface FetchResult {
  readonly workspacePath: string;
  readonly artifactPath: string;
}

export function resolveWorkspacePath(scanId: string, workspaceRoot = tmpdir()): string {
  return join(workspaceRoot, WORKSPACE_PREFIX, scanId);
}

export async function prepareWorkspace(scanId: string, workspaceRoot?: string): Promise<string> {
  const basePath = workspaceRoot ?? tmpdir();
  const workspacePath = resolveWorkspacePath(scanId, basePath);
  await fs.rm(workspacePath, { recursive: true, force: true });
  await fs.mkdir(workspacePath, { recursive: true });
  return workspacePath;
}

export async function cleanupWorkspace(workspacePath: string): Promise<void> {
  await fs.rm(workspacePath, { recursive: true, force: true });
}

function getFetchImplementation(options?: FetchOptions): typeof fetch {
  return options?.fetchImpl ?? fetch;
}

function resolveBinary(defaultName: string, envKey: string): string {
  const override = process.env[envKey];

  if (typeof override === 'string') {
    const trimmed = override.trim();

    if (trimmed.length > 0) {
      return trimmed;
    }
  }

  return defaultName;
}

async function runCommand(command: string, args: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    execFile(command, args, { timeout: EXEC_TIMEOUT_MS }, (error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

async function runCommandOutput(command: string, args: string[]): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    execFile(command, args, { timeout: EXEC_TIMEOUT_MS }, (error, stdout = '') => {
      if (error) {
        reject(error);
        return;
      }

      resolve(stdout);
    });
  });
}

function isUnsafePath(name: string): boolean {
  const normalized = name.replace(/\\/gu, '/');

  if (!normalized || normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized)) {
    return true;
  }

  const segments = normalized.split('/');
  for (const segment of segments) {
    if (segment === '..') {
      return true;
    }
  }

  return false;
}

function parseTarEntries(output: string): ArchiveEntry[] {
  const entries: ArchiveEntry[] = [];
  for (const rawLine of output.split('\n')) {
    const line = rawLine.trimEnd();
    if (!line) {
      continue;
    }

    const match = line.match(/^(?<mode>.{10})\s+\d+\/\d+\s+\d+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(?<rest>.+)$/u);
    if (!match?.groups) {
      continue;
    }

    const { mode, rest } = match.groups as { mode: string; rest: string };
    let name = rest;
    let linkTarget: string | undefined;

    const arrowIndex = rest.indexOf(' -> ');
    if (arrowIndex >= 0) {
      name = rest.slice(0, arrowIndex);
      linkTarget = rest.slice(arrowIndex + 4);
    }

    const typeChar = mode.charAt(0);
    const type: ArchiveEntry['type'] =
      typeChar === 'd' ? 'directory' : typeChar === 'l' ? 'symlink' : typeChar === '-' ? 'file' : 'other';

    entries.push({ name, type, linkTarget });
  }

  return entries;
}

function parseZipEntries(output: string): ArchiveEntry[] {
  const entries: ArchiveEntry[] = [];
  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();

    if (
      !line ||
      line.startsWith('Archive:') ||
      line.startsWith('Zip file size:') ||
      /files?, \d+ bytes/iu.test(line)
    ) {
      continue;
    }

    const match = line.match(
      /^(?<mode>.{10})\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\S+\s+\d{2}-[A-Za-z]{3}-\d{2}\s+\d{2}:\d{2}\s+(?<name>.+)$/u
    );
    if (!match?.groups) {
      continue;
    }

    const { mode, name } = match.groups as { mode: string; name: string };
    let entryName = name;
    let linkTarget: string | undefined;

    const arrowIndex = entryName.indexOf(' -> ');
    if (arrowIndex >= 0) {
      linkTarget = entryName.slice(arrowIndex + 4);
      entryName = entryName.slice(0, arrowIndex);
    }

    const typeChar = mode.charAt(0);
    const type: ArchiveEntry['type'] =
      typeChar === 'd' ? 'directory' : typeChar === 'l' ? 'symlink' : typeChar === '-' ? 'file' : 'other';

    entries.push({ name: entryName, type, linkTarget });
  }

  return entries;
}

async function ensureArchiveIsSafe(type: ArchiveType, archivePath: string): Promise<void> {
  const entries =
    type === 'zip'
      ? parseZipEntries(await runCommandOutput(resolveBinary('unzip', UNZIP_BIN_ENV), ['-Z', '-l', archivePath]))
      : parseTarEntries(await runCommandOutput(resolveBinary('tar', TAR_BIN_ENV), ['-tvf', archivePath]));

  for (const entry of entries) {
    if (isUnsafePath(entry.name)) {
      throw new Error(`Archive entry contains an unsafe path: ${entry.name}`);
    }

    if (entry.type === 'symlink') {
      const target = entry.linkTarget;
      if (!target || isUnsafePath(target)) {
        throw new Error(`Archive contains an unsafe symlink: ${entry.name}`);
      }
    }
  }
}

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value : '';
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

function isGitUrlAllowed(url: string): boolean {
  if (url.startsWith('https://')) {
    return true;
  }

  if (url.startsWith('ssh://') || url.startsWith('git+ssh://')) {
    return true;
  }

  return /^[^@]+@[^:]+:.+/u.test(url);
}

function ensureHttpsUrl(rawUrl: string, context: string): URL {
  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`${context} must be a valid HTTPS URL.`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`${context} must use HTTPS.`);
  }

  return parsed;
}

type GuardedLookupCallback = (
  error: PrivateAddressError | null,
  address?: string,
  family?: number
) => void;

function createGuardedLookup(context: string) {
  return (
    hostname: string,
    options: { family?: number; hints?: number; all?: boolean },
    callback: GuardedLookupCallback
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
        const normalized = error instanceof Error ? error : new Error(String(error));
        callback(normalized as PrivateAddressError);
      });
  };
}

async function ensurePublicHostname(hostname: string, context: string): Promise<void> {
  const trimmed = hostname.trim();

  if (!trimmed) {
    throw new Error(`${context} must include a hostname.`);
  }

  const normalizedHost =
    trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1) : trimmed;
  const lowered = normalizedHost.toLowerCase();

  if (lowered === 'localhost' || lowered.endsWith('.local')) {
    throw new Error(`${context} resolves to a private address.`);
  }

  if (isIP(normalizedHost)) {
    if (isPrivateAddress(normalizedHost)) {
      throw new Error(`${context} resolves to a private address.`);
    }

    return;
  }

  const records = await lookup(normalizedHost, { all: true });

  if (records.length === 0) {
    throw new Error(`${context} host could not be resolved.`);
  }

  if (records.some((record) => isPrivateAddress(record.address))) {
    throw new Error(`${context} resolves to a private address.`);
  }
}

async function createPublicDispatcher(url: URL, context: string): Promise<GuardedDispatcher> {
  await ensurePublicHostname(url.hostname, context);

  const rawHostname = url.hostname;
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
          callback: GuardedLookupCallback
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
      lookup: createGuardedLookup(context)
    }
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return agent;
}

async function closeGuardedDispatcher(dispatcher: GuardedDispatcher): Promise<void> {
  const maybeClose = (dispatcher as { close?: DispatcherCloseFn }).close;
  if (typeof maybeClose === 'function') {
    await maybeClose.call(dispatcher);
  }
}

async function destroyGuardedDispatcher(dispatcher: GuardedDispatcher): Promise<void> {
  const maybeDestroy = (dispatcher as { destroy?: DispatcherDestroyFn }).destroy;
  if (typeof maybeDestroy === 'function') {
    await maybeDestroy.call(dispatcher);
  }
}

async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  options: FetchRequestOptions,
  timeoutMs: number,
  timeoutMessage: string
): Promise<FetchResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetchImpl(url, { ...options, signal: controller.signal } as FetchRequestOptions);
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      throw new Error(timeoutMessage);
    }

    throw error instanceof Error ? error : new Error(String(error));
  } finally {
    clearTimeout(timer);
  }
}

function isAbortError(error: unknown): boolean {
  if (error && typeof error === 'object' && 'name' in error) {
    return (error as { name?: unknown }).name === 'AbortError';
  }

  return false;
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function wrapTimeoutError(error: unknown, timeoutMessage: string): Error {
  return isAbortError(error) ? new Error(timeoutMessage) : toError(error);
}

function createTimeoutGuard(timeoutMs: number): TimeoutGuard {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | null = null;

  const schedule = () => {
    if (timer) {
      clearTimeout(timer);
    }

    timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
  };

  schedule();

  return {
    controller,
    reset(): void {
      schedule();
    },
    clear(): void {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    }
  };
}

function extractSshHostname(url: string): string | null {
  if (url.startsWith('ssh://') || url.startsWith('git+ssh://')) {
    const normalized = url.startsWith('git+ssh://') ? url.slice(4) : url;
    try {
      const parsed = new URL(normalized);
      return parsed.hostname;
    } catch {
      return null;
    }
  }

  const match = url.match(/^[^@]+@([^:]+):.+$/u);
  return match ? match[1] : null;
}

async function ensureGitHostIsPublic(repoUrl: string): Promise<void> {
  const context = 'Git artifact URL';

  if (repoUrl.startsWith('https://')) {
    const parsed = ensureHttpsUrl(repoUrl, context);
    await ensurePublicHostname(parsed.hostname, context);
    return;
  }

  const hostname = extractSshHostname(repoUrl);

  if (!hostname) {
    throw new Error('Git artifact URL must include a hostname.');
  }

  await ensurePublicHostname(hostname, context);
}

function resolveGitHostname(repoUrl: string): string {
  if (repoUrl.startsWith('https://')) {
    return ensureHttpsUrl(repoUrl, 'Git artifact URL').host;
  }

  const hostname = extractSshHostname(repoUrl);

  if (!hostname) {
    throw new Error('Git artifact URL must include a hostname.');
  }

  return hostname;
}

function isGitRedirectFailure(error: unknown): boolean {
  const rawStderr = (error as { stderr?: unknown })?.stderr;
  const stderr =
    typeof rawStderr === 'string'
      ? rawStderr
      : Buffer.isBuffer(rawStderr)
        ? rawStderr.toString('utf8')
        : '';
  const message = error instanceof Error ? error.message : String(error ?? '');
  return /redirect/i.test(stderr) || /redirect/i.test(message);
}

async function fetchGitArtifact(
  workspacePath: string,
  artifactPath: string,
  definition: ArtifactDefinition
): Promise<void> {
  assertNetworkFetchAllowed('git artifacts');

  const repoUrl = normalizeString(definition.ref.url);

  if (!repoUrl) {
    throw new Error('Git artifact requires a ref.url value.');
  }

  if (!isGitUrlAllowed(repoUrl)) {
    throw new Error('Git artifact URL must use HTTPS or SSH.');
  }

  await ensureGitHostIsPublic(repoUrl);

  const gitHostname = resolveGitHostname(repoUrl);
  const gitHostKey = circuitKeyFromHost(gitHostname);

  if (!allowArtifactAttempt(gitHostKey, Date.now())) {
    throw new Error(
      `Network fetches to ${gitHostname} are temporarily disabled due to repeated failures. Try again later.`
    );
  }

  const branch = normalizeString(definition.ref.branch);
  const commit = normalizeString(definition.ref.commit);

  const cloneArgs = ['-c', 'http.followRedirects=false', 'clone', '--depth', '1', '--no-tags'];

  if (branch) {
    cloneArgs.push('--branch', branch);
  }

  cloneArgs.push('--', repoUrl, artifactPath);

  try {
    await runCommand(resolveBinary('git', GIT_BIN_ENV), cloneArgs);
    recordArtifactSuccess(gitHostKey);
  } catch (error) {
    recordArtifactFailure(gitHostKey, Date.now());
    if (isGitRedirectFailure(error)) {
      throw new Error(
        'Git clone was blocked because the remote attempted an HTTP redirect; supply a direct HTTPS or SSH repository URL.'
      );
    }

    throw (error instanceof Error ? error : new Error(String(error)));
  }

  if (commit) {
    await runCommand(resolveBinary('git', GIT_BIN_ENV), ['-C', artifactPath, 'checkout', commit]);
  }
}

async function fetchArchiveArtifact(
  workspacePath: string,
  artifactPath: string,
  definition: ArtifactDefinition,
  fetchImpl: typeof fetch
): Promise<void> {
  assertNetworkFetchAllowed('archive artifacts');

  const url = normalizeString(definition.ref.url);

  if (!url) {
    throw new Error('Archive artifact requires a ref.url value.');
  }

  const normalizedUrlObject = ensureHttpsUrl(url, 'Archive artifact URL');
  const normalizedUrl = normalizedUrlObject.toString();
  const hostKey = circuitKeyFromHost(normalizedUrlObject.host);

  if (!allowArtifactAttempt(hostKey, Date.now())) {
    throw new Error(
      `Network downloads to ${normalizedUrlObject.host} are temporarily disabled due to repeated failures. Try again later.`
    );
  }

  const dispatcher: GuardedDispatcher = await createPublicDispatcher(
    normalizedUrlObject,
    'Archive artifact URL'
  );
  let dispatcherError: Error | undefined;
  let dispatcherCloseError: unknown;
  const archivePath = join(workspacePath, 'download');
  const checksum = normalizeString(definition.ref.sha256);
  const hash = checksum ? createHash('sha256') : null;
  let reader: StreamReader | undefined;
  let fileHandle: fs.FileHandle | null = null;

  async function closeFileHandle(): Promise<void> {
    if (fileHandle) {
      await fileHandle.close().catch(() => {});
      fileHandle = null;
    }
  }

  try {
    const headers: Record<string, string> = {};
    const response: FetchResponse = await fetchWithTimeout(
      fetchImpl,
      normalizedUrl,
      {
        headers,
        redirect: 'manual',
        dispatcher
      } as FetchRequestOptions,
      FETCH_TIMEOUT_MS,
      `Request to ${normalizedUrl} timed out.`
    );

    if (response.status >= 300 && response.status < 400) {
      throw new Error(`Request to ${normalizedUrl} attempted redirect with status ${response.status}.`);
    }

    if (!response.ok) {
      throw new Error(`Request to ${normalizedUrl} failed with status ${response.status}.`);
    }

    const contentLengthHeader = response.headers.get('content-length');
    const declaredLength =
      contentLengthHeader !== null ? Number(contentLengthHeader) : undefined;

    if (
      typeof declaredLength === 'number' &&
      Number.isFinite(declaredLength) &&
      declaredLength > MAX_ARCHIVE_SIZE
    ) {
      throw new Error(
        `Archive download declared size ${declaredLength} exceeds limit ${MAX_ARCHIVE_SIZE} bytes.`
      );
    }

    const body = response.body as unknown as WebStreamLike;

    if (!body || typeof body.getReader !== 'function') {
      throw new Error(`Request to ${normalizedUrl} returned an empty body.`);
    }

    reader = body.getReader();
    fileHandle = await fs.open(archivePath, 'w');
    let bytesWritten = 0;

    while (true) {
      const { value, done } = await reader.read();

      if (done) {
        break;
      }

      if (!value) {
        continue;
      }

      bytesWritten += value.byteLength;

      if (
        typeof declaredLength === 'number' &&
        Number.isFinite(declaredLength) &&
        bytesWritten > declaredLength
      ) {
        await reader.cancel().catch(() => {});
        throw new Error(`Archive download exceeded declared size of ${declaredLength} bytes.`);
      }

      if (bytesWritten > MAX_ARCHIVE_SIZE) {
        await reader.cancel().catch(() => {});
        throw new Error(`Archive download exceeded ${MAX_ARCHIVE_SIZE} bytes.`);
      }

      hash?.update(value);
      await fileHandle.write(value);
    }

    if (checksum && hash) {
      const digest = hash.digest('hex');

      if (digest !== checksum) {
        throw new Error('Archive checksum mismatch.');
      }
    }

    recordArtifactSuccess(hostKey);
  } catch (error) {
    if (reader) {
      await reader.cancel().catch(() => {});
    }

    await closeFileHandle();
    await fs.rm(archivePath, { force: true }).catch(() => {});

    const normalizedError = error instanceof Error ? error : new Error(String(error));
    dispatcherError = normalizedError;
    recordArtifactFailure(hostKey, Date.now());
    throw normalizedError;
  } finally {
    await closeFileHandle();

    if (dispatcherError) {
      try {
        await destroyGuardedDispatcher(dispatcher);
      } catch {
        // ignore dispatcher destroy errors in failure path
      }
    } else {
      try {
        await closeGuardedDispatcher(dispatcher);
      } catch (closeError) {
        dispatcherCloseError = closeError;
      }
    }
  }

  if (dispatcherCloseError) {
    throw dispatcherCloseError instanceof Error
      ? dispatcherCloseError
      : new Error(String(dispatcherCloseError));
  }

  await fs.mkdir(artifactPath, { recursive: true });
  try {
    const loweredUrl = normalizedUrl.toLowerCase();
    if (loweredUrl.endsWith('.zip')) {
      await ensureArchiveIsSafe('zip', archivePath);
      await runCommand(resolveBinary('unzip', UNZIP_BIN_ENV), ['-q', '-X', archivePath, '-d', artifactPath]);
    } else {
      await ensureArchiveIsSafe('tar', archivePath);
      await runCommand(resolveBinary('tar', TAR_BIN_ENV), [
        '--extract',
        '--file',
        archivePath,
        '--directory',
        artifactPath,
        '--no-same-owner',
        '--no-same-permissions',
        '--delay-directory-restore'
      ]);
    }
  } finally {
    await fs.rm(archivePath, { force: true });
  }
}

function buildAuthHeader(ref: Record<string, unknown>): string | undefined {
  const auth = ref.auth as Record<string, unknown> | undefined;

  if (!auth) {
    return undefined;
  }

  const type = normalizeString(auth.type).toLowerCase();

  if (type === 'basic') {
    const username = normalizeString(auth.username);
    const password = normalizeString(auth.password);

    if (username && password) {
      const token = Buffer.from(`${username}:${password}`, 'utf-8').toString('base64');
      return `Basic ${token}`;
    }
  }

  if (type === 'bearer') {
    const token = normalizeString(auth.token);

    if (token) {
      return `Bearer ${token}`;
    }
  }

  return undefined;
}

async function fetchOciArtifact(
  workspacePath: string,
  artifactPath: string,
  definition: ArtifactDefinition,
  fetchImpl: typeof fetch
): Promise<void> {
  assertNetworkFetchAllowed('oci artifacts');

  const registry = normalizeString(definition.ref.registry);
  const repository = normalizeString(definition.ref.repository);
  const digest = normalizeString(definition.ref.digest);
  const tag = normalizeString(definition.ref.tag);

  if (!registry || !repository) {
    throw new Error('OCI artifacts require registry and repository references.');
  }

  const reference = digest || tag;

  if (!reference) {
    throw new Error('OCI artifacts require a digest or tag reference.');
  }

  const registryUrl = ensureHttpsUrl(registry, 'OCI registry URL');
  const registryHostKey = circuitKeyFromHost(registryUrl.host);

  if (!allowArtifactAttempt(registryHostKey, Date.now())) {
    throw new Error(
      `Network downloads to ${registryUrl.host} are temporarily disabled due to repeated failures. Try again later.`
    );
  }

  const dispatcher: GuardedDispatcher = await createPublicDispatcher(registryUrl, 'OCI registry URL');
  let dispatcherError: Error | undefined;
  let dispatcherCloseError: unknown;

  try {
    const registryBase = `${registryUrl.origin}${registryUrl.pathname.replace(/\/$/u, '')}`;
    const baseUrl = `${registryBase}/v2/${repository}`;
    const headers: Record<string, string> = {
      accept: 'application/vnd.oci.image.manifest.v1+json'
    };

    const authHeader = buildAuthHeader(definition.ref);

    if (authHeader) {
      headers.authorization = authHeader;
    }

    const manifestTimeout = createTimeoutGuard(FETCH_TIMEOUT_MS);
    let manifestResponse: FetchResponse;

    try {
      manifestResponse = await fetchImpl(
        `${baseUrl}/manifests/${reference}`,
        {
          headers,
          redirect: 'manual',
          dispatcher,
          signal: manifestTimeout.controller.signal
        } as FetchRequestOptions
      );
    } catch (error) {
      throw wrapTimeoutError(error, `OCI manifest request for ${reference} timed out.`);
    } finally {
      manifestTimeout.clear();
    }

    if (manifestResponse.status >= 300 && manifestResponse.status < 400) {
      throw new Error(`OCI manifest request attempted redirect with status ${manifestResponse.status}`);
    }

    if (!manifestResponse.ok) {
      throw new Error(`Failed to retrieve OCI manifest: ${manifestResponse.status}`);
    }

    const manifest = (await manifestResponse.json()) as {
      layers: Array<{ digest: string; mediaType?: string; size?: number }>;
    };

    if (!Array.isArray(manifest.layers) || manifest.layers.length === 0) {
      throw new Error('OCI manifest did not contain any layers.');
    }

    await fs.mkdir(artifactPath, { recursive: true });

    for (const layer of manifest.layers) {
      const layerDigest = normalizeString(layer.digest);

      if (!layerDigest) {
        continue;
      }

      const manifestDeclaredSize =
        typeof layer.size === 'number' && Number.isFinite(layer.size) ? Number(layer.size) : undefined;

      if (
        typeof manifestDeclaredSize === 'number' &&
        manifestDeclaredSize > MAX_ARCHIVE_SIZE
      ) {
        throw new Error(
          `OCI layer ${layerDigest} declared size ${manifestDeclaredSize} exceeds limit ${MAX_ARCHIVE_SIZE} bytes.`
        );
      }

      const layerTimeout = createTimeoutGuard(FETCH_TIMEOUT_MS);
      let layerResponse: FetchResponse;

      try {
        layerResponse = await fetchImpl(
          `${baseUrl}/blobs/${layerDigest}`,
          {
            headers,
            redirect: 'manual',
            dispatcher,
            signal: layerTimeout.controller.signal
          } as FetchRequestOptions
        );
      } catch (error) {
        layerTimeout.clear();
        throw wrapTimeoutError(error, `OCI layer request for ${layerDigest} timed out.`);
      }

      if (layerResponse.status >= 300 && layerResponse.status < 400) {
        throw new Error(
          `OCI layer request attempted redirect for ${layerDigest}: ${layerResponse.status}`
        );
      }

      if (!layerResponse.ok) {
        throw new Error(`Failed to download OCI layer ${layerDigest}: ${layerResponse.status}`);
      }

      const contentLengthHeader = layerResponse.headers.get('content-length');
      const declaredLength =
        contentLengthHeader !== null ? Number(contentLengthHeader) : undefined;

      if (
        typeof declaredLength === 'number' &&
        Number.isFinite(declaredLength) &&
        declaredLength > MAX_ARCHIVE_SIZE
      ) {
        throw new Error(
          `OCI layer ${layerDigest} declared Content-Length ${declaredLength} exceeds limit ${MAX_ARCHIVE_SIZE} bytes.`
        );
      }

      if (
        typeof manifestDeclaredSize === 'number' &&
        typeof declaredLength === 'number' &&
        Number.isFinite(manifestDeclaredSize) &&
        Number.isFinite(declaredLength) &&
        declaredLength > manifestDeclaredSize
      ) {
        throw new Error(
          `OCI layer ${layerDigest} Content-Length ${declaredLength} exceeds manifest size ${manifestDeclaredSize}.`
        );
      }

      const body = layerResponse.body as unknown as WebStreamLike;

      if (!body || typeof body.getReader !== 'function') {
        layerTimeout.clear();
        throw new Error(`OCI layer ${layerDigest} response did not include a body.`);
      }

      const layerPath = join(artifactPath, layerDigest.replace(/[:/]/gu, '_'));
      let layerReader: StreamReader | undefined;
      let layerHandle: fs.FileHandle | null = null;
      const expectedPrefix = layerDigest.split(':')[0];
      const expectedChecksum = layerDigest.split(':')[1];
      const checksumHash =
        expectedPrefix === 'sha256' && expectedChecksum ? createHash('sha256') : null;

      async function closeLayerHandle(): Promise<void> {
        if (layerHandle) {
          await layerHandle.close().catch(() => {});
          layerHandle = null;
        }
      }

      try {
        layerReader = body.getReader();
        layerTimeout.reset();
        layerHandle = await fs.open(layerPath, 'w');
        let bytesWritten = 0;

        while (true) {
          const { value, done } = await layerReader.read();
          layerTimeout.reset();

          if (done) {
            break;
          }

          if (!value) {
            continue;
          }

          bytesWritten += value.byteLength;

          if (
            typeof manifestDeclaredSize === 'number' &&
            Number.isFinite(manifestDeclaredSize) &&
            bytesWritten > manifestDeclaredSize
          ) {
            await layerReader.cancel().catch(() => {});
            throw new Error(
              `OCI layer ${layerDigest} exceeded manifest size of ${manifestDeclaredSize} bytes.`
            );
          }

          if (bytesWritten > MAX_ARCHIVE_SIZE) {
            await layerReader.cancel().catch(() => {});
            throw new Error(`OCI layer ${layerDigest} exceeded ${MAX_ARCHIVE_SIZE} bytes.`);
          }

          checksumHash?.update(value);
          await layerHandle.write(value);
        }

        if (checksumHash && expectedChecksum) {
          const digest = checksumHash.digest('hex');

          if (digest !== expectedChecksum) {
            throw new Error(`Layer checksum mismatch for ${layerDigest}.`);
          }
        }
      } catch (layerError) {
        if (layerReader) {
          await layerReader.cancel().catch(() => {});
        }

        await closeLayerHandle();
        await fs.rm(layerPath, { force: true }).catch(() => {});

        throw wrapTimeoutError(layerError, `OCI layer request for ${layerDigest} timed out.`);
      } finally {
        layerTimeout.clear();
        await closeLayerHandle();
      }
    }
    recordArtifactSuccess(registryHostKey);
  } catch (error) {
    const normalizedError = error instanceof Error ? error : new Error(String(error));
    dispatcherError = normalizedError;
    recordArtifactFailure(registryHostKey, Date.now());
    throw normalizedError;
  } finally {
    if (dispatcherError) {
      try {
        await destroyGuardedDispatcher(dispatcher);
      } catch {
        // ignore dispatcher destroy errors on failure
      }
    } else {
      try {
        await closeGuardedDispatcher(dispatcher);
      } catch (closeError) {
        dispatcherCloseError = closeError;
      }
    }
  }

  if (dispatcherCloseError) {
    throw dispatcherCloseError instanceof Error
      ? dispatcherCloseError
      : new Error(String(dispatcherCloseError));
  }
}

export async function fetchArtifact(options: FetchOptions): Promise<FetchResult> {
  const workspacePath = await prepareWorkspace(options.scanId, options.workspaceRoot);
  const artifactPath = join(workspacePath, 'source');

  if (options.artifact.type === 'git') {
    await fetchGitArtifact(workspacePath, artifactPath, options.artifact);
  } else if (options.artifact.type === 'archive') {
    await fetchArchiveArtifact(workspacePath, artifactPath, options.artifact, getFetchImplementation(options));
  } else if (options.artifact.type === 'oci') {
    await fetchOciArtifact(workspacePath, artifactPath, options.artifact, getFetchImplementation(options));
  } else {
    throw new Error(`Unsupported artifact type: ${String(options.artifact.type)}`);
  }

  return { workspacePath, artifactPath };
}
