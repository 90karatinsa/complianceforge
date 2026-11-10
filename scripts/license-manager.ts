// SPDX-License-Identifier: MIT

import {
  appendFile,
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import process from 'node:process';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  hkdfSync,
  randomBytes,
  randomUUID,
  verify
} from 'node:crypto';
import { pathToFileURL } from 'node:url';

import keytar from 'keytar';

const KEYTAR_SERVICE = 'otomatik-oss-license';
const KEYTAR_ACCOUNT = 'primary';
const DEFAULT_PRODUCT_ID = 'otomatik-oss-suite';
const LOG_DIRECTORY = ['.config', 'otomatik-oss'];
const LOG_FILE_NAME = 'license.log';
const LOG_MAX_BYTES = 5 * 1024 * 1024;
const LOG_MAX_BACKUPS = 2;
// Hardware fingerprint normalization order (lower-case, trimmed, whitespace collapsed):
// 1. hostname
// 2. arch
// 3. platform
// 4. cpu_model
// 5. cpu_speed_mhz
// 6. cpu_count
// 7. machine_id
const FALLBACK_HW_SEED = 'alterra-hw-fingerprint-seed-v1';
const HARDWARE_CLAIM_ORDER = [
  'hostname',
  'arch',
  'platform',
  'cpu_model',
  'cpu_speed_mhz',
  'cpu_count',
  'machine_id'
] as const;
const SEALED_SECRET_ALGORITHM = 'AES-256-GCM';
const SEALED_SECRET_INFO = 'alterra-license-secret-v1';
const SEALED_SECRET_TAG_BYTES = 16;
const EULA_ACCEPTANCE_FILE = 'eula.json';
const CURRENT_EULA_VERSION = '2024.06';
const EULA_OUTDATED_MESSAGE =
  'EULA acceptance is required. Re-run with --accept-eula (or --accept-eula=<version>) to continue.';

type EnvRecord = Record<string, string | undefined>;

interface LicenseManagerDependencies {
  readonly env: EnvRecord;
  readonly now: () => Date;
  readonly randomBytes: (size: number) => Buffer;
  readonly randomUUID: () => string;
  readonly createHash: typeof createHash;
  readonly createHmac: typeof createHmac;
  readonly createCipheriv: typeof createCipheriv;
  readonly createDecipheriv: typeof createDecipheriv;
  readonly createPublicKey: typeof createPublicKey;
  readonly hkdfSync: typeof hkdfSync;
  readonly verify: typeof verify;
  readonly readFile: typeof readFile;
  readonly writeFile: typeof writeFile;
  readonly appendFile: typeof appendFile;
  readonly open: typeof open;
  readonly rename: typeof rename;
  readonly chmod: typeof chmod;
  readonly stat: typeof stat;
  readonly lstat: typeof lstat;
  readonly mkdir: typeof mkdir;
  readonly homedir: typeof os.homedir;
  readonly hostname: typeof os.hostname;
  readonly arch: typeof os.arch;
  readonly platform: typeof os.platform;
  readonly cpus: typeof os.cpus;
  readonly keytar: Pick<typeof keytar, 'setPassword' | 'getPassword' | 'deletePassword'>;
}

interface BaseOptions {
  readonly dependencies?: Partial<LicenseManagerDependencies>;
  readonly logger?: (message: string) => void;
}

interface LicenseRequestOptions extends BaseOptions {
  readonly outputPath?: string;
  readonly productId?: string;
  readonly licenseId?: string;
  readonly requestNonce?: string;
}

interface LicenseRequestPayload {
  readonly license_id: string;
  readonly product_id: string;
  readonly hw_fingerprint: string;
  readonly request_nonce: string;
  readonly requested_at: string;
}

interface LicenseResponseEnvelope {
  readonly signature: string;
  readonly license: LicenseBody | string;
  readonly payload: string;
}

interface InstallLicenseOptions extends BaseOptions {
  readonly responsePath?: string;
  readonly response?: LicenseResponseEnvelope;
  readonly productId?: string;
  readonly publicKey?: string;
  readonly purge?: boolean;
}

interface LicenseBody {
  readonly license_id: string;
  readonly product_id: string;
  readonly hw_fingerprint: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly features: string[];
  readonly revoked?: boolean;
  readonly aes_key: string;
  readonly aes_iv: string;
}

interface StoredLicenseRecord {
  readonly license: LicenseBody;
  readonly signature: string;
  readonly secret: SealedSecretBlob;
  readonly installed_at: string;
  readonly last_validated_at: string;
}

interface SealedSecretBlob {
  readonly algorithm: typeof SEALED_SECRET_ALGORITHM;
  readonly info: typeof SEALED_SECRET_INFO;
  readonly salt: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

interface EulaAcceptanceRecord {
  readonly version: string;
  readonly accepted_at: string;
}

interface InstallLicenseResult {
  readonly licenseId: string;
  readonly expiresAt: string;
  readonly features: readonly string[];
  readonly installedAt: string;
  readonly secret: string;
}

interface LicenseStatusOptions extends BaseOptions {
  readonly productId?: string;
  readonly publicKey?: string;
}

interface LicenseStatusResult {
  readonly licenseId: string;
  readonly status: 'active' | 'expired' | 'revoked';
  readonly expiresAt: string;
  readonly features: readonly string[];
  readonly lastValidatedAt: string;
  readonly warnings: readonly string[];
}

interface PurgeLicenseOptions extends BaseOptions {}

type SortedJson = string | number | boolean | null | undefined | SortedJson[] | { [key: string]: SortedJson };

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

function ensureStringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`License field ${field} must be a non-empty string.`);
  }
  return value;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function ensureStringArray(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!isStringArray(value)) {
    throw new Error('License features must be an array of strings.');
  }
  return value;
}

function resolveDependencies(overrides?: Partial<LicenseManagerDependencies>): LicenseManagerDependencies {
  const env: EnvRecord = overrides?.env ?? process.env;
  const now = overrides?.now ?? (() => new Date());
  const randomBytesImpl = overrides?.randomBytes ?? randomBytes;
  const randomUuidImpl = overrides?.randomUUID ?? randomUUID;
  const createHashImpl = overrides?.createHash ?? createHash;
  const createHmacImpl = overrides?.createHmac ?? createHmac;
  const createCipherImpl = overrides?.createCipheriv ?? createCipheriv;
  const createDecipherImpl = overrides?.createDecipheriv ?? createDecipheriv;
  const createPublicKeyImpl = overrides?.createPublicKey ?? createPublicKey;
  const hkdfSyncImpl = overrides?.hkdfSync ?? hkdfSync;
  const verifyImpl = overrides?.verify ?? verify;
  const readFileImpl = overrides?.readFile ?? readFile;
  const writeFileImpl = overrides?.writeFile ?? writeFile;
  const appendFileImpl = overrides?.appendFile ?? appendFile;
  const openImpl = overrides?.open ?? open;
  const renameImpl = overrides?.rename ?? rename;
  const chmodImpl = overrides?.chmod ?? chmod;
  const statImpl = overrides?.stat ?? stat;
  const lstatImpl = overrides?.lstat ?? lstat;
  const mkdirImpl = overrides?.mkdir ?? mkdir;
  const homedirImpl = overrides?.homedir ?? os.homedir;
  const hostnameImpl = overrides?.hostname ?? os.hostname;
  const archImpl = overrides?.arch ?? os.arch;
  const platformImpl = overrides?.platform ?? os.platform;
  const cpusImpl = overrides?.cpus ?? os.cpus;
  const keytarImpl = overrides?.keytar ?? keytar;

  return {
    env,
    now,
    randomBytes: randomBytesImpl,
    randomUUID: randomUuidImpl,
    createHash: createHashImpl,
    createHmac: createHmacImpl,
    createCipheriv: createCipherImpl,
    createDecipheriv: createDecipherImpl,
    createPublicKey: createPublicKeyImpl,
    hkdfSync: hkdfSyncImpl,
    verify: verifyImpl,
    readFile: readFileImpl,
    writeFile: writeFileImpl,
    appendFile: appendFileImpl,
    open: openImpl,
    rename: renameImpl,
    chmod: chmodImpl,
    stat: statImpl,
    lstat: lstatImpl,
    mkdir: mkdirImpl,
    homedir: homedirImpl,
    hostname: hostnameImpl,
    arch: archImpl,
    platform: platformImpl,
    cpus: cpusImpl,
    keytar: keytarImpl
  };
}

function encodeBase64Url(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=/gu, '')
    .replace(/\+/gu, '-')
    .replace(/\//gu, '_');
}

const BASE64URL_CANONICAL_PATTERN = /^[A-Za-z0-9_-]+$/u;

function decodeBase64Url(input: string, field: string): Buffer {
  if (typeof input !== 'string' || input.length === 0) {
    throw new Error(`Field ${field} must be a non-empty base64url string.`);
  }

  if (input.includes('=') || !BASE64URL_CANONICAL_PATTERN.test(input)) {
    throw new Error(`Field ${field} must be canonical base64url data.`);
  }

  const normalized = input.replace(/-/gu, '+').replace(/_/gu, '/');
  const remainder = normalized.length % 4;
  if (remainder === 1) {
    throw new Error(`Field ${field} is not valid base64url data.`);
  }
  const padded = normalized + (remainder === 0 ? '' : '='.repeat(4 - remainder));

  let decoded: Buffer;
  try {
    decoded = Buffer.from(padded, 'base64');
  } catch (error) {
    throw new Error(`Field ${field} is not valid base64url data.`, {
      cause: error instanceof Error ? error : undefined
    });
  }

  if (decoded.length === 0) {
    throw new Error(`Field ${field} decoded to an empty value.`);
  }

  if (encodeBase64Url(decoded) !== input) {
    throw new Error(`Field ${field} must be canonical base64url data.`);
  }

  return decoded;
}

function parseSealedSecret(raw: unknown): SealedSecretBlob {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Stored license secret must be an object.');
  }
  const candidate = raw as Record<string, unknown>;
  const algorithm = ensureStringField(candidate, 'algorithm');
  if (algorithm !== SEALED_SECRET_ALGORITHM) {
    throw new Error(`Stored license secret algorithm must be ${SEALED_SECRET_ALGORITHM}.`);
  }
  const info = ensureStringField(candidate, 'info');
  if (info !== SEALED_SECRET_INFO) {
    throw new Error('Stored license secret info marker is invalid.');
  }
  const salt = ensureStringField(candidate, 'salt');
  const nonce = ensureStringField(candidate, 'nonce');
  const ciphertext = ensureStringField(candidate, 'ciphertext');
  const tag = ensureStringField(candidate, 'tag');

  const saltBytes = decodeBase64Url(salt, 'secret.salt');
  const nonceBytes = decodeBase64Url(nonce, 'secret.nonce');
  const tagBytes = decodeBase64Url(tag, 'secret.tag');
  decodeBase64Url(ciphertext, 'secret.ciphertext');
  if (saltBytes.length !== 32) {
    throw new Error('Stored license secret salt must be 32 bytes.');
  }
  if (nonceBytes.length !== 12) {
    throw new Error('Stored license secret nonce must be 12 bytes.');
  }
  if (tagBytes.length !== SEALED_SECRET_TAG_BYTES) {
    throw new Error('Stored license secret tag must be 16 bytes.');
  }

  return {
    algorithm: SEALED_SECRET_ALGORITHM,
    info: SEALED_SECRET_INFO,
    salt,
    nonce,
    ciphertext,
    tag
  } satisfies SealedSecretBlob;
}

function unsealSecret(
  deps: LicenseManagerDependencies,
  sealed: SealedSecretBlob,
  signatureBytes: Buffer,
  fingerprint: string
): string {
  const salt = decodeBase64Url(sealed.salt, 'secret.salt');
  const nonce = decodeBase64Url(sealed.nonce, 'secret.nonce');
  const ciphertext = decodeBase64Url(sealed.ciphertext, 'secret.ciphertext');
  const tag = decodeBase64Url(sealed.tag, 'secret.tag');

  const ikm = Buffer.concat([signatureBytes, Buffer.from(fingerprint, 'utf8')]);
  const key = deps.hkdfSync('sha256', ikm, salt, SEALED_SECRET_INFO, 32);
  const decipher = deps.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

function resolveConfigDirectory(deps: LicenseManagerDependencies): string {
  return path.join(deps.homedir(), ...LOG_DIRECTORY);
}

async function ensureLogDirectory(deps: LicenseManagerDependencies): Promise<string> {
  const directory = resolveConfigDirectory(deps);
  await deps.mkdir(directory, { recursive: true, mode: 0o700 });

  try {
    const lstatResult = await deps.lstat(directory);

    if (lstatResult.isSymbolicLink()) {
      throw new Error('License log directory must not be a symbolic link.');
    }

    if (deps.platform() === 'win32') {
      return directory;
    }

    const stats = await deps.stat(directory);
    const permissions = stats.mode & 0o777;

    if ((permissions & 0o077) !== 0 || permissions !== 0o700) {
      await deps.chmod(directory, 0o700);
      const updated = await deps.stat(directory);
      const updatedPermissions = updated.mode & 0o777;

      if ((updatedPermissions & 0o077) !== 0 || updatedPermissions !== 0o700) {
        throw new Error('License log directory permissions must not grant group or world access.');
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

interface LicenseLogEntry {
  readonly action: string;
  readonly licenseId?: string | null;
  readonly status?: string | null;
  readonly metadata?: Record<string, unknown> | undefined;
}

interface LicenseLogRecord {
  readonly timestamp: string;
  readonly action: string;
  readonly license_id: string | null;
  readonly status: string | null;
  readonly metadata?: Record<string, unknown>;
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
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};

    for (const [key, entry] of Object.entries(input)) {
      const normalizedKey = key.toLowerCase();
      if (/secret|token|key|credential|password/iu.test(normalizedKey)) {
        output[key] = '***';
        continue;
      }

      output[key] = sanitizeMetadata(entry);
    }

    return output;
  }

  return String(value);
}

function createLogRecord(deps: LicenseManagerDependencies, entry: LicenseLogEntry): LicenseLogRecord {
  const base: LicenseLogRecord = {
    timestamp: deps.now().toISOString(),
    action: entry.action,
    license_id: entry.licenseId ?? null,
    status: entry.status ?? null
  };

  if (entry.metadata && Object.keys(entry.metadata).length > 0) {
    base.metadata = sanitizeMetadata(entry.metadata) as Record<string, unknown>;
  }

  return base;
}

async function assertWritableLogTarget(
  deps: LicenseManagerDependencies,
  logPath: string
): Promise<void> {
  try {
    const stats = await deps.lstat(logPath);
    if (typeof stats.isSymbolicLink === 'function' && stats.isSymbolicLink()) {
      throw new Error('License log file must not be a symlink.');
    }
    if (typeof stats.isFile === 'function' && !stats.isFile()) {
      throw new Error('License log target must be a regular file.');
    }
    if (deps.platform() !== 'win32') {
      const permissions = stats.mode & 0o777;
      if ((permissions & 0o077) !== 0) {
        throw new Error('License log file permissions must not grant group or world access.');
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

async function rotateLogsIfNeeded(deps: LicenseManagerDependencies, logPath: string): Promise<void> {
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

  for (let index = LOG_MAX_BACKUPS; index >= 1; index -= 1) {
    const source = index === 1 ? logPath : `${logPath}.${index - 1}`;
    const target = `${logPath}.${index}`;
    try {
      await deps.rename(source, target);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT') {
        throw error;
      }
    }
  }

  await assertWritableLogTarget(deps, logPath);
  await deps.writeFile(logPath, '', { encoding: 'utf8', mode: 0o600 });
}

async function logLicenseEvent(deps: LicenseManagerDependencies, entry: LicenseLogEntry): Promise<void> {
  const directory = await ensureLogDirectory(deps);
  const logPath = path.join(directory, LOG_FILE_NAME);
  await rotateLogsIfNeeded(deps, logPath);
  const record = createLogRecord(deps, entry);
  await assertWritableLogTarget(deps, logPath);
  await deps.appendFile(logPath, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
}

function normalizeIdentifier(value: unknown): string {
  if (typeof value !== 'string') {
    return 'unavailable';
  }
  const trimmed = value.trim().toLowerCase().replace(/\s+/gu, ' ');
  return trimmed.length > 0 ? trimmed : 'unavailable';
}

function normalizeNumber(value: unknown): string {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    return '0';
  }
  const rounded = Math.round(value);
  return rounded >= 0 ? String(rounded) : '0';
}

function normalizeMachineIdentifier(value: string | undefined): string {
  if (!value) {
    return 'unavailable';
  }
  const trimmed = value.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : 'unavailable';
}

async function computeHardwareFingerprint(deps: LicenseManagerDependencies): Promise<string> {
  const seed = deps.env.LICENSE_HW_SEED;
  const hmacKey = seed && seed.trim().length > 0 ? seed.trim() : FALLBACK_HW_SEED;

  const claims: Record<(typeof HARDWARE_CLAIM_ORDER)[number], string> = {
    hostname: normalizeIdentifier(deps.hostname()),
    arch: normalizeIdentifier(deps.arch()),
    platform: normalizeIdentifier(deps.platform()),
    cpu_model: 'unavailable',
    cpu_speed_mhz: '0',
    cpu_count: '0',
    machine_id: 'unavailable'
  };

  const cpus = deps.cpus();
  if (Array.isArray(cpus) && cpus.length > 0) {
    const primary = cpus[0];
    const model = normalizeIdentifier(typeof primary?.model === 'string' ? primary.model : undefined);
    const speed = normalizeNumber(typeof primary?.speed === 'number' ? primary.speed : undefined);
    claims.cpu_model = model;
    claims.cpu_speed_mhz = speed;
    claims.cpu_count = normalizeNumber(cpus.length);
  }

  const machineIdCandidates = ['/etc/machine-id', '/var/lib/dbus/machine-id'];
  for (const candidate of machineIdCandidates) {
    try {
      const raw = await deps.readFile(candidate, 'utf8');
      claims.machine_id = normalizeMachineIdentifier(raw);
      if (claims.machine_id !== 'unavailable') {
        break;
      }
    } catch {
      // ignore missing machine identifier
    }
  }

  const canonicalParts = HARDWARE_CLAIM_ORDER.map((key) => `${key}=${claims[key]}`);
  const hmac = deps.createHmac('sha256', Buffer.from(hmacKey, 'utf8'));
  hmac.update(canonicalParts.join('|'), 'utf8');
  return encodeBase64Url(hmac.digest());
}

function resolveEulaMarkerPath(deps: LicenseManagerDependencies): string {
  return path.join(resolveConfigDirectory(deps), EULA_ACCEPTANCE_FILE);
}

interface SystemEulaMarker {
  readonly path: string;
  readonly directory: string;
  readonly platform: NodeJS.Platform;
}

function resolveSystemEulaMarker(deps: LicenseManagerDependencies): SystemEulaMarker | null {
  const platform = deps.platform();

  if (platform === 'darwin') {
    const directory = path.posix.join('/Library/Application Support', 'Atlas SCA');
    return {
      path: path.posix.join(directory, 'eula.accepted'),
      directory,
      platform
    } satisfies SystemEulaMarker;
  }

  if (platform === 'win32') {
    let programData =
      typeof deps.env.PROGRAMDATA === 'string' && deps.env.PROGRAMDATA.trim().length > 0
        ? deps.env.PROGRAMDATA.trim()
        : 'C\\\\ProgramData';

    if (/^[A-Za-z](?!:)/u.test(programData)) {
      programData = `${programData[0]}:${programData.slice(1)}`;
    }

    programData = path.win32.normalize(programData);

    const directory = path.win32.join(programData, 'Atlas SCA');
    return {
      path: path.win32.join(directory, 'eula.accepted'),
      directory,
      platform
    } satisfies SystemEulaMarker;
  }

  return null;
}

async function persistSystemEulaMarker(
  deps: LicenseManagerDependencies,
  record: EulaAcceptanceRecord
): Promise<void> {
  const marker = resolveSystemEulaMarker(deps);

  if (!marker) {
    return;
  }

  try {
    const directoryMode = marker.platform === 'darwin' ? 0o700 : undefined;
    await deps.mkdir(marker.directory, { recursive: true, mode: directoryMode });
    const payload = `${JSON.stringify(record, null, 2)}\n`;
    await deps.writeFile(marker.path, payload, { encoding: 'utf8', mode: 0o600 });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to persist system EULA acceptance marker: ${message}`);
  }
}

async function readEulaAcceptance(
  deps: LicenseManagerDependencies
): Promise<EulaAcceptanceRecord | undefined> {
  const markerPath = resolveEulaMarkerPath(deps);
  try {
    const raw = await deps.readFile(markerPath, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const version = ensureStringField(parsed, 'version');
    const acceptedAt = ensureStringField(parsed, 'accepted_at');
    return { version, accepted_at: acceptedAt } satisfies EulaAcceptanceRecord;
  } catch (error) {
    const failure = toError(error);
    if (/ENOENT/iu.test(failure.message) || /no such file/iu.test(failure.message)) {
      return undefined;
    }
    throw new Error(`Failed to read EULA acceptance marker: ${failure.message}`);
  }
}

async function persistEulaAcceptance(
  deps: LicenseManagerDependencies,
  version: string,
  logger?: (message: string) => void
): Promise<EulaAcceptanceRecord> {
  const record: EulaAcceptanceRecord = {
    version,
    accepted_at: deps.now().toISOString()
  };
  const directory = await ensureLogDirectory(deps);
  const markerPath = path.join(directory, EULA_ACCEPTANCE_FILE);
  await persistJsonFile(deps, markerPath, record);
  await persistSystemEulaMarker(deps, record);
  await logLicenseEvent(deps, {
    action: 'eula.accepted',
    licenseId: null,
    status: 'accepted',
    metadata: { version }
  });
  logger?.(`EULA version ${version} accepted.`);
  return record;
}

async function ensureEulaAccepted(
  deps: LicenseManagerDependencies,
  acceptanceFlag: string | undefined,
  logger?: (message: string) => void
): Promise<EulaAcceptanceRecord> {
  if (acceptanceFlag !== undefined) {
    const trimmed = acceptanceFlag.trim();
    const requestedVersion = trimmed.length > 0 ? trimmed : CURRENT_EULA_VERSION;
    if (requestedVersion !== CURRENT_EULA_VERSION) {
      throw new Error(
        `EULA acceptance requires version ${CURRENT_EULA_VERSION}, but received ${requestedVersion}. Re-run with --accept-eula=${CURRENT_EULA_VERSION}.`
      );
    }
    return persistEulaAcceptance(deps, CURRENT_EULA_VERSION, logger);
  }

  const existing = await readEulaAcceptance(deps);
  if (!existing) {
    throw new Error(EULA_OUTDATED_MESSAGE);
  }

  if (existing.version !== CURRENT_EULA_VERSION) {
    throw new Error(
      `${EULA_OUTDATED_MESSAGE} (stored version ${existing.version}, required ${CURRENT_EULA_VERSION}).`
    );
  }

  return existing;
}

function ensureProductId(value: string | undefined, deps: LicenseManagerDependencies): string {
  return value ?? deps.env.LICENSE_PRODUCT_ID ?? DEFAULT_PRODUCT_ID;
}

function canonicalize(value: unknown): SortedJson {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }

  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const result: Record<string, SortedJson> = {};
    for (const key of sortedKeys) {
      const normalized = canonicalize(record[key]);
      if (normalized === undefined) {
        continue;
      }
      result[key] = normalized;
    }
    return result;
  }

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
    return value;
  }

  return undefined;
}

function parseLicenseBody(raw: unknown): LicenseBody {
  if (!raw || typeof raw !== 'object') {
    throw new Error('License payload must be an object.');
  }

  const candidate = raw as Record<string, unknown>;
  const licenseId = ensureStringField(candidate, 'license_id');
  const productId = ensureStringField(candidate, 'product_id');
  const hwFingerprint = ensureStringField(candidate, 'hw_fingerprint');
  const issuedAt = ensureStringField(candidate, 'issued_at');
  const expiresAt = ensureStringField(candidate, 'expires_at');
  const aesKey = ensureStringField(candidate, 'aes_key');
  const aesIv = ensureStringField(candidate, 'aes_iv');
  const featuresValue = ensureStringArray(candidate, 'features');

  const revokedRaw = candidate.revoked;
  if (revokedRaw !== undefined && typeof revokedRaw !== 'boolean') {
    throw new Error('License revoked flag must be a boolean when present.');
  }

  return {
    license_id: licenseId,
    product_id: productId,
    hw_fingerprint: hwFingerprint,
    issued_at: issuedAt,
    expires_at: expiresAt,
    features: featuresValue,
    revoked: typeof revokedRaw === 'boolean' ? revokedRaw : undefined,
    aes_key: aesKey,
    aes_iv: aesIv
  };
}

function normalizeLicenseEnvelope(raw: LicenseBody | string): LicenseBody {
  if (typeof raw === 'string') {
    return parseLicenseBody(JSON.parse(raw) as unknown);
  }
  return parseLicenseBody(raw);
}

function validateLicenseChronology(license: LicenseBody, now: Date): void {
  const issuedAt = new Date(license.issued_at);
  const expiresAt = new Date(license.expires_at);

  if (Number.isNaN(issuedAt.getTime())) {
    throw new Error('License issued_at is not a valid ISO-8601 timestamp.');
  }

  if (Number.isNaN(expiresAt.getTime())) {
    throw new Error('License expires_at is not a valid ISO-8601 timestamp.');
  }

  if (now < issuedAt) {
    throw new Error('System clock is behind license issue time.');
  }

  if (now > expiresAt) {
    throw new Error('License is already expired.');
  }
}

async function persistJsonFile(
  deps: LicenseManagerDependencies,
  targetPath: string,
  payload: unknown
): Promise<void> {
  const directory = path.dirname(targetPath);
  await deps.mkdir(directory, { recursive: true });
  const content = `${JSON.stringify(payload, null, 2)}\n`;
  const safeUuid = deps.randomUUID().replace(/[^a-zA-Z0-9]/gu, '');
  const tempPath = `${targetPath}.${safeUuid}.tmp`;
  const handle = await deps.open(tempPath, 'w', 0o600);
  try {
    await handle.writeFile(content, { encoding: 'utf8' });
    if (typeof handle.sync === 'function') {
      await handle.sync();
    }
  } catch (error) {
    await handle.close();
    throw error;
  }
  await handle.close();
  try {
    await deps.rename(tempPath, targetPath);
  } catch (error) {
    await deps.stat(targetPath).catch(() => undefined);
    throw error;
  }
}

async function createLicenseRequest(options: LicenseRequestOptions = {}): Promise<LicenseRequestPayload> {
  const deps = resolveDependencies(options.dependencies);
  const licenseId = options.licenseId ?? deps.env.LICENSE_ID ?? deps.randomUUID();
  const productId = ensureProductId(options.productId, deps);
  const nonce = options.requestNonce ?? deps.env.LICENSE_REQUEST_NONCE ?? encodeBase64Url(deps.randomBytes(24));
  const fingerprint = await computeHardwareFingerprint(deps);
  const requestedAt = deps.now().toISOString();

  const payload: LicenseRequestPayload = {
    license_id: licenseId,
    product_id: productId,
    hw_fingerprint: fingerprint,
    request_nonce: nonce,
    requested_at: requestedAt
  };

  if (options.outputPath) {
    await persistJsonFile(deps, path.resolve(options.outputPath), payload);
  }

  await logLicenseEvent(deps, {
    action: 'license.requested',
    licenseId,
    status: 'generated'
  });
  options.logger?.(`License request prepared for ${licenseId}`);

  return payload;
}

function decryptPayload(
  deps: LicenseManagerDependencies,
  license: LicenseBody,
  payload: string
): string {
  const key = decodeBase64Url(license.aes_key, 'license.aes_key');
  const iv = decodeBase64Url(license.aes_iv, 'license.aes_iv');
  const encrypted = decodeBase64Url(payload, 'payload');
  if (key.length !== 32) {
    throw new Error('License AES key must be 32 bytes.');
  }
  if (iv.length !== 12) {
    throw new Error('License AES IV must be 12 bytes.');
  }
  if (encrypted.length < 16) {
    throw new Error('Encrypted payload is too small to contain authentication tag.');
  }

  const ciphertext = encrypted.subarray(0, encrypted.length - 16);
  const tag = encrypted.subarray(encrypted.length - 16);
  const decipher = deps.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

async function installLicense(options: InstallLicenseOptions = {}): Promise<InstallLicenseResult> {
  const deps = resolveDependencies(options.dependencies);
  let currentLicenseId: string | undefined;

  try {
    if (options.purge === true) {
      await purgeLicense({ dependencies: options.dependencies, logger: options.logger });
      throw new Error('License store purged.');
    }

    const envelope =
      options.response ??
      (await (async () => {
        if (!options.responsePath) {
          throw new Error('Response path must be provided when no response object is supplied.');
        }
        const raw = await deps.readFile(path.resolve(options.responsePath), 'utf8');
        return JSON.parse(raw) as LicenseResponseEnvelope;
      })());

    const license = normalizeLicenseEnvelope(envelope.license);
    currentLicenseId = license.license_id;
    const expectedProductId = ensureProductId(options.productId, deps);
    if (license.product_id !== expectedProductId) {
      throw new Error('License product_id does not match this installation.');
    }

    const fingerprint = await computeHardwareFingerprint(deps);
    if (license.hw_fingerprint !== fingerprint) {
      throw new Error('License hardware fingerprint does not match this node.');
    }

    if (license.revoked) {
      throw new Error('License has been revoked.');
    }

    const now = deps.now();
    validateLicenseChronology(license, now);

    const canonical = JSON.stringify(canonicalize(license));
    const signature = decodeBase64Url(envelope.signature, 'signature');
    const canonicalInputSignature = envelope.signature
      .replace(/=+$/gu, '')
      .replace(/\+/gu, '-')
      .replace(/\//gu, '_');
    const recodedSignature = encodeBase64Url(signature);
    if (recodedSignature !== canonicalInputSignature) {
      throw new Error('License signature verification failed.');
    }
    const publicKeyBase64 = options.publicKey ?? deps.env.LICENSE_PUBLIC_KEY;
    if (!publicKeyBase64) {
      throw new Error('LICENSE_PUBLIC_KEY environment variable is required.');
    }
    const publicKeyBytes = decodeBase64Url(publicKeyBase64, 'LICENSE_PUBLIC_KEY');
    const publicKey = deps.createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    const verified = deps.verify(null, Buffer.from(canonical, 'utf8'), publicKey, signature);
    if (!verified) {
      throw new Error('License signature verification failed.');
    }

    const secret = decryptPayload(deps, license, envelope.payload);

    const salt = deps.randomBytes(32);
    const nonce = deps.randomBytes(12);
    const ikm = Buffer.concat([signature, Buffer.from(fingerprint, 'utf8')]);
    const key = deps.hkdfSync('sha256', ikm, salt, SEALED_SECRET_INFO, 32);
    const cipher = deps.createCipheriv('aes-256-gcm', key, nonce);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(secret, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();

    const sealedSecret: SealedSecretBlob = {
      algorithm: SEALED_SECRET_ALGORITHM,
      info: SEALED_SECRET_INFO,
      salt: encodeBase64Url(salt),
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
      tag: encodeBase64Url(tag)
    };

    const record: StoredLicenseRecord = {
      license,
      signature: envelope.signature,
      secret: sealedSecret,
      installed_at: now.toISOString(),
      last_validated_at: now.toISOString()
    };

    await deps.keytar.setPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT, JSON.stringify(record));
    await logLicenseEvent(deps, {
      action: 'license.installed',
      licenseId: license.license_id,
      status: 'installed',
      metadata: { expires_at: license.expires_at }
    });
    options.logger?.(`License ${license.license_id} installed.`);

    return {
      licenseId: license.license_id,
      expiresAt: license.expires_at,
      features: license.features,
      installedAt: record.installed_at,
      secret
    };
  } catch (error) {
    const failure = toError(error);
    await logLicenseEvent(deps, {
      action: 'license.install_failed',
      licenseId: currentLicenseId ?? null,
      status: 'failed',
      metadata: { reason: failure.message }
    });
    throw failure;
  }
}

async function readStoredLicense(
  deps: LicenseManagerDependencies
): Promise<StoredLicenseRecord | undefined> {
  const stored = await deps.keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
  if (!stored) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(stored) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Stored license payload must be an object.');
    }

    const candidate = parsed as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(candidate, 'license')) {
      throw new Error('Stored license record is missing required field: license.');
    }

    const license = parseLicenseBody(candidate.license);
    const signature = candidate.signature;
    if (typeof signature !== 'string' || signature.length === 0) {
      throw new Error('Stored license signature must be a non-empty string.');
    }

    const secretValue = parseSealedSecret(candidate.secret);

    const installedAt = candidate.installed_at;
    if (typeof installedAt !== 'string' || installedAt.length === 0) {
      throw new Error('Stored license installed_at must be a non-empty string.');
    }

    const lastValidatedAt = candidate.last_validated_at;
    if (typeof lastValidatedAt !== 'string' || lastValidatedAt.length === 0) {
      throw new Error('Stored license last_validated_at must be a non-empty string.');
    }

    return {
      license,
      signature,
      secret: secretValue,
      installed_at: installedAt,
      last_validated_at: lastValidatedAt
    } satisfies StoredLicenseRecord;
  } catch (error) {
    const failure = toError(error);
    throw new Error(`Stored license data is invalid: ${failure.message}`);
  }
}

async function getLicenseStatus(options: LicenseStatusOptions = {}): Promise<LicenseStatusResult> {
  const deps = resolveDependencies(options.dependencies);
  let currentLicenseId: string | undefined;

  try {
    const record = await readStoredLicense(deps);
    if (!record) {
      throw new Error('No license is currently installed.');
    }

    const license = record.license;
    currentLicenseId = license.license_id;
    const fingerprint = await computeHardwareFingerprint(deps);
    if (license.hw_fingerprint !== fingerprint) {
      throw new Error('Installed license does not belong to this node.');
    }

    const canonical = JSON.stringify(canonicalize(license));
    const publicKeyBase64 = options.publicKey ?? deps.env.LICENSE_PUBLIC_KEY;
    if (!publicKeyBase64) {
      throw new Error('LICENSE_PUBLIC_KEY environment variable is required.');
    }
    const publicKeyBytes = decodeBase64Url(publicKeyBase64, 'LICENSE_PUBLIC_KEY');
    const publicKey = deps.createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    const signature = decodeBase64Url(record.signature, 'signature');
    const canonicalStoredSignature = record.signature
      .replace(/=+$/gu, '')
      .replace(/\+/gu, '-')
      .replace(/\//gu, '_');
    if (encodeBase64Url(signature) !== canonicalStoredSignature) {
      throw new Error('Stored license signature is malformed.');
    }
    const verified = deps.verify(null, Buffer.from(canonical, 'utf8'), publicKey, signature);
    if (!verified) {
      throw new Error('Stored license signature verification failed.');
    }

    try {
      unsealSecret(deps, record.secret, signature, fingerprint);
    } catch (error) {
      const failure = toError(error);
      throw new Error(`Stored license secret cannot be decrypted: ${failure.message}`);
    }

    const now = deps.now();
    let status: 'active' | 'expired' | 'revoked' = 'active';
    const warnings: string[] = [];

    const expiresAtDate = new Date(license.expires_at);
    if (Number.isNaN(expiresAtDate.getTime())) {
      throw new Error('Stored license has invalid expiration timestamp.');
    }

    if (license.revoked) {
      status = 'revoked';
      warnings.push('License is revoked.');
    } else if (now > expiresAtDate) {
      status = 'expired';
      warnings.push('License has expired.');
    }

    const updated: StoredLicenseRecord = {
      ...record,
      last_validated_at: now.toISOString()
    };

    await deps.keytar.setPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT, JSON.stringify(updated));
    await logLicenseEvent(deps, {
      action: 'license.status_checked',
      licenseId: license.license_id,
      status,
      metadata: { expires_at: license.expires_at }
    });
    options.logger?.(`License ${license.license_id} status: ${status}`);

    return {
      licenseId: license.license_id,
      status,
      expiresAt: license.expires_at,
      features: license.features,
      lastValidatedAt: updated.last_validated_at,
      warnings
    };
  } catch (error) {
    const failure = toError(error);
    if (failure.message.startsWith('Stored license data is invalid')) {
      try {
        await deps.keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
      } catch {
        // ignore purge failures to avoid masking the original error
      }
      await logLicenseEvent(deps, {
        action: 'license.corrupted_purged',
        licenseId: currentLicenseId ?? null,
        status: 'purged',
        metadata: { reason: failure.message }
      });
    }
    await logLicenseEvent(deps, {
      action: 'license.status_failed',
      licenseId: currentLicenseId ?? null,
      status: 'failed',
      metadata: { reason: failure.message }
    });
    throw failure;
  }
}

async function purgeLicense(options: PurgeLicenseOptions = {}): Promise<void> {
  const deps = resolveDependencies(options.dependencies);
  const deleted = await deps.keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
  if (!deleted) {
    throw new Error('No license data found to purge.');
  }
  await logLicenseEvent(deps, {
    action: 'license.purged',
    licenseId: null,
    status: 'purged'
  });
  options.logger?.('License store purged.');
}

interface ParsedCliArguments {
  readonly command: string | undefined;
  readonly flags: Map<string, string | boolean>;
  readonly positionals: string[];
}

function parseCliArguments(argv: readonly string[]): ParsedCliArguments {
  const flags = new Map<string, string | boolean>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token) {
      continue;
    }
    if (token.startsWith('--')) {
      const [rawKey, rawValue] = token.slice(2).split('=', 2);
      if (!rawKey) {
        continue;
      }
      if (rawValue !== undefined) {
        flags.set(rawKey, rawValue);
        continue;
      }
      const next = argv[i + 1];
      if (next && !next.startsWith('-')) {
        flags.set(rawKey, next);
        i += 1;
      } else {
        flags.set(rawKey, true);
      }
      continue;
    }
    if (token.startsWith('-')) {
      flags.set(token.slice(1), true);
      continue;
    }
    positionals.push(token);
  }

  const [command, ...rest] = positionals;
  return { command, flags, positionals: rest };
}

function resolveFlagBoolean(flags: Map<string, string | boolean>, key: string): boolean {
  const value = flags.get(key);
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const normalized = value.toLowerCase();
    return normalized === 'true' || normalized === '1' || normalized === 'yes';
  }
  return false;
}

function resolveFlagString(flags: Map<string, string | boolean>, key: string): string | undefined {
  if (!flags.has(key)) {
    return undefined;
  }
  const value = flags.get(key);
  if (typeof value === 'string') {
    return value;
  }
  if (value === true) {
    return '';
  }
  return undefined;
}

async function cli(
  argv: readonly string[],
  dependencyOverrides?: Partial<LicenseManagerDependencies>
): Promise<void> {
  const { command, flags } = parseCliArguments(argv);
  const logger = (message: string) => process.stdout.write(`${message}\n`);

  const resolveCliDependencies = () => resolveDependencies(dependencyOverrides);

  if (flags.has('help') || command === 'help') {
    process.stdout.write(
      'Usage: license-manager <request|install|status|purge> [--flags]\n' +
        'Flags:\n' +
        '  --accept-eula[=<version>]  Accept the ComplianceForge lisans (MIT) (required for install/status).\n' +
        '  --public-key <base64url>   Provide the Ed25519 public key for verification.\n' +
        '  --purge                    Remove stored license secrets.\n'
    );
    return;
  }

  switch (command) {
    case 'request': {
      const outputPath = (flags.get('output') as string | undefined) ?? undefined;
      const productId = (flags.get('product') as string | undefined) ?? undefined;
      const licenseId = (flags.get('license') as string | undefined) ?? undefined;
      const nonce = (flags.get('nonce') as string | undefined) ?? undefined;
      const payload = await createLicenseRequest({
        outputPath,
        productId,
        licenseId,
        requestNonce: nonce,
        dependencies: resolveCliDependencies(),
        logger
      });
      process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
      return;
    }
    case 'install': {
      const dependencies = resolveCliDependencies();
      if (resolveFlagBoolean(flags, 'purge')) {
        await purgeLicense({ dependencies, logger });
        return;
      }
      await ensureEulaAccepted(dependencies, resolveFlagString(flags, 'accept-eula'), logger);
      const responsePath = (flags.get('response') as string | undefined) ?? undefined;
      const productId = (flags.get('product') as string | undefined) ?? undefined;
      const publicKey = (flags.get('public-key') as string | undefined) ?? undefined;
      const result = await installLicense({
        responsePath,
        productId,
        publicKey,
        dependencies,
        logger
      });
      process.stdout.write(
        `License ${result.licenseId} active until ${result.expiresAt} with features: ${result.features.join(', ')}\n`
      );
      return;
    }
    case 'status': {
      const dependencies = resolveCliDependencies();
      await ensureEulaAccepted(dependencies, resolveFlagString(flags, 'accept-eula'), logger);
      const productId = (flags.get('product') as string | undefined) ?? undefined;
      const publicKey = (flags.get('public-key') as string | undefined) ?? undefined;
      const status = await getLicenseStatus({ productId, publicKey, dependencies, logger });
      process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
      return;
    }
    case 'purge': {
      const dependencies = resolveCliDependencies();
      await purgeLicense({ dependencies, logger });
      return;
    }
    default:
      throw new Error('Usage: license-manager <request|install|status|purge> [--flags] (see --help).');
  }
}

function isExecutedDirectly(): boolean {
  const entryPoint = process.argv[1];
  if (!entryPoint) {
    return false;
  }
  return import.meta.url === pathToFileURL(entryPoint).href;
}

if (isExecutedDirectly()) {
  cli(process.argv.slice(2)).catch((error: unknown) => {
    const failure = error instanceof Error ? error : new Error(String(error));
    process.stderr.write(`License manager error: ${failure.message}\n`);
    process.exitCode = 1;
  });
}

export {
  createLicenseRequest,
  getLicenseStatus,
  installLicense,
  cli as licenseManagerCli,
  purgeLicense,
  type InstallLicenseResult,
  type LicenseRequestPayload,
  type LicenseStatusResult
};
