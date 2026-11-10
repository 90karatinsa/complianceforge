// SPDX-License-Identifier: MIT

import {
  KeyObject,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  hkdfSync,
  sign,
  verify
} from 'node:crypto';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createLicenseRequest,
  getLicenseStatus,
  installLicense,
  licenseManagerCli,
  purgeLicense,
  type LicenseRequestPayload
} from '../../scripts/license-manager.ts';

vi.mock('keytar', () => ({
  default: {
    setPassword: () => Promise.resolve(),
    getPassword: () => Promise.resolve(null),
    deletePassword: () => Promise.resolve(true)
  }
}));

interface TestEnvironment {
  readonly dependencies: Record<string, unknown>;
  readonly files: Map<string, string>;
  readonly logs: string[];
  readonly keytarStore: Map<string, string>;
  readonly writeOptions: Map<string, unknown>;
  readonly appendOptions: Map<string, unknown>;
  readonly mkdirMock: ReturnType<typeof vi.fn>;
  readonly chmodMock: ReturnType<typeof vi.fn>;
  setDirectory(path: string, mode: number): void;
  setFile(path: string, contents: string, options?: { mode?: number; symlink?: boolean }): void;
  setNow(value: Date): void;
}

let publicKeyDer: Buffer;
let privateKey: KeyObject;

function encodeBase64Url(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=/gu, '')
    .replace(/\+/gu, '-')
    .replace(/\//gu, '_');
}

function decodeBase64Url(value: string): Buffer {
  const normalized = value.replace(/-/gu, '+').replace(/_/gu, '/');
  const padding = normalized.length % 4;
  const padded = normalized + (padding === 2 ? '==' : padding === 3 ? '=' : padding === 0 ? '' : '===');
  return Buffer.from(padded, 'base64');
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const normalized: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      normalized[key] = canonicalize(record[key]);
    }
    return normalized;
  }
  return value;
}

function setupEnvironment(): TestEnvironment {
  const files = new Map<string, string>();
  const logs: string[] = [];
  const keytarStore = new Map<string, string>();
  const writeOptions = new Map<string, unknown>();
  const appendOptions = new Map<string, unknown>();
  const directoryModes = new Map<string, number>();
  const fileModes = new Map<string, number>();
  const symlinkTargets = new Set<string>();
  let currentNow = new Date('2024-06-01T12:00:00.000Z');

  const applyFileState = (targetPath: string, contents: string, mode: number, isSymlink: boolean) => {
    files.set(targetPath, contents);
    fileModes.set(targetPath, mode);
    if (isSymlink) {
      symlinkTargets.add(targetPath);
    } else {
      symlinkTargets.delete(targetPath);
    }
  };

  const mkdirMock = vi.fn(
    async (targetPath: string, options?: { recursive?: boolean; mode?: number }) => {
      if (!directoryModes.has(targetPath)) {
        directoryModes.set(targetPath, options?.mode ?? 0o777);
      }
    }
  );

  const chmodMock = vi.fn(async (targetPath: string, mode: number) => {
    directoryModes.set(targetPath, mode);
  });

  const createStatRecord = (mode: number, kind: 'file' | 'directory' | 'symlink', size: number) => ({
    size,
    mode,
    isSymbolicLink: () => kind === 'symlink',
    isFile: () => kind === 'file',
    isDirectory: () => kind === 'directory'
  });

  const statMock = vi.fn(async (targetPath: string) => {
    if (directoryModes.has(targetPath)) {
      return createStatRecord(directoryModes.get(targetPath)!, 'directory', 0);
    }

    const value = files.get(targetPath);
    if (value === undefined) {
      const error = new Error(`ENOENT: ${targetPath}`);
      (error as NodeJS.ErrnoException).code = 'ENOENT';
      throw error;
    }

    const mode = fileModes.get(targetPath) ?? 0o600;
    const kind = symlinkTargets.has(targetPath) ? 'symlink' : 'file';
    return createStatRecord(mode, kind, Buffer.byteLength(value, 'utf8'));
  });

  const lstatMock = vi.fn(async (targetPath: string) => statMock(targetPath));

  const openMock = vi.fn(
    async (targetPath: string, _flags: string, mode: number = 0o666) => {
      const handle: Pick<FileHandle, 'writeFile' | 'sync' | 'close'> = {
        async writeFile(data: string, options?: string | { encoding?: string }) {
          if (typeof options === 'string' && options !== 'utf8') {
            throw new Error(`Unsupported encoding: ${options}`);
          }
          if (options && typeof options === 'object' && options.encoding && options.encoding !== 'utf8') {
            throw new Error(`Unsupported encoding: ${options.encoding}`);
          }
          applyFileState(targetPath, data, mode, false);
          writeOptions.set(targetPath, { encoding: 'utf8', mode });
        },
        async sync() {
          /* no-op for tests */
        },
        async close() {
          /* no-op for tests */
        }
      };
      return handle as FileHandle;
    }
  );

  const dependencies = {
    env: {
      LICENSE_HW_SEED: 'seed-123',
      LICENSE_PUBLIC_KEY: encodeBase64Url(publicKeyDer),
      LICENSE_PRODUCT_ID: 'product-alpha'
    },
    now: () => new Date(currentNow.getTime()),
    randomBytes: (size: number) => Buffer.alloc(size, 0xaa),
    randomUUID: () => 'uuid-fixed',
    createHash,
    createHmac,
    createCipheriv,
    createDecipheriv,
    createPublicKey,
    hkdfSync,
    verify,
    readFile: (targetPath: string, encoding: string) => {
      if (targetPath === '/etc/machine-id' || targetPath === '/var/lib/dbus/machine-id') {
        return Promise.resolve('machine-id-value');
      }
      const value = files.get(targetPath);
      if (value === undefined) {
        return Promise.reject(new Error(`ENOENT: ${targetPath}`));
      }
      if (encoding !== 'utf8') {
        return Promise.reject(new Error(`Unsupported encoding: ${encoding}`));
      }
      return Promise.resolve(value);
    },
    writeFile: (targetPath: string, data: string, options?: string | { encoding?: string; mode?: number }) => {
      if (typeof options === 'string') {
        if (options !== 'utf8') {
          return Promise.reject(new Error(`Unsupported encoding: ${options}`));
        }
        writeOptions.set(targetPath, { encoding: options });
      } else if (options && typeof options === 'object') {
        if (options.encoding && options.encoding !== 'utf8') {
          return Promise.reject(new Error(`Unsupported encoding: ${options.encoding}`));
        }
        writeOptions.set(targetPath, { ...options });
      } else {
        writeOptions.set(targetPath, {});
      }

      const mode =
        typeof options === 'object' && options && typeof options.mode === 'number'
          ? options.mode
          : fileModes.get(targetPath) ?? 0o666;
      applyFileState(targetPath, data, mode, false);
      return Promise.resolve();
    },
    appendFile: (
      targetPath: string,
      data: string,
      options?: string | { encoding?: string; mode?: number }
    ) => {
      if (typeof options === 'string') {
        if (options !== 'utf8') {
          return Promise.reject(new Error(`Unsupported encoding: ${options}`));
        }
        appendOptions.set(targetPath, { encoding: options });
      } else if (options && typeof options === 'object') {
        if (options.encoding && options.encoding !== 'utf8') {
          return Promise.reject(new Error(`Unsupported encoding: ${options.encoding}`));
        }
        appendOptions.set(targetPath, { ...options });
      } else {
        appendOptions.set(targetPath, {});
      }

      const previous = files.get(targetPath) ?? '';
      const mode =
        typeof options === 'object' && options && typeof options.mode === 'number'
          ? options.mode
          : fileModes.get(targetPath) ?? 0o666;
      applyFileState(targetPath, `${previous}${data}`, mode, false);
      logs.push(`${targetPath}:${data}`);
      return Promise.resolve();
    },
    rename: (source: string, destination: string) => {
      if (!files.has(source)) {
        const error = new Error(`ENOENT: ${source}`);
        (error as NodeJS.ErrnoException).code = 'ENOENT';
        return Promise.reject(error);
      }
      const value = files.get(source) ?? '';
      const mode = fileModes.get(source) ?? 0o600;
      const isSymlink = symlinkTargets.has(source);
      files.delete(source);
      fileModes.delete(source);
      symlinkTargets.delete(source);
      applyFileState(destination, value, mode, isSymlink);
      logs.push(`rename:${source}->${destination}`);
      return Promise.resolve();
    },
    stat: statMock,
    lstat: lstatMock,
    open: openMock,
    mkdir: mkdirMock,
    chmod: chmodMock,
    homedir: () => '/home/tester',
    hostname: () => 'test-host',
    arch: () => 'x64',
    platform: () => 'linux',
    cpus: () => [
      {
        model: 'Test CPU',
        speed: 3200,
        times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 }
      }
    ],
    keytar: {
      setPassword: (service: string, account: string, value: string) => {
        keytarStore.set(`${service}:${account}`, value);
        return Promise.resolve();
      },
      getPassword: (service: string, account: string) =>
        Promise.resolve(keytarStore.get(`${service}:${account}`) ?? null),
      deletePassword: (service: string, account: string) =>
        Promise.resolve(keytarStore.delete(`${service}:${account}`))
    }
  } satisfies Record<string, unknown>;

  return {
    dependencies,
    files,
    logs,
    keytarStore,
    writeOptions,
    appendOptions,
    mkdirMock,
    chmodMock,
    setDirectory(path: string, mode: number) {
      directoryModes.set(path, mode);
    },
    setFile(path: string, contents: string, options?: { mode?: number; symlink?: boolean }) {
      const mode = options?.mode ?? fileModes.get(path) ?? 0o600;
      const isSymlink = options?.symlink ?? false;
      applyFileState(path, contents, mode, isSymlink);
    },
    setNow(value: Date) {
      currentNow = new Date(value.getTime());
    }
  } satisfies TestEnvironment;
}

function readLicenseLogEntries(environment: TestEnvironment): Record<string, unknown>[] {
  const logPath = path.join('/home/tester', '.config', 'otomatik-oss', 'license.log');
  const contents = environment.files.get(logPath) ?? '';
  return contents
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function createLicenseResponseFromPlaintext(
  request: LicenseRequestPayload,
  plaintext: Buffer,
  issuedAt: string,
  expiresAt: string
) {
  const key = Buffer.alloc(32, 0xbb);
  const iv = Buffer.alloc(12, 0xcc);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = Buffer.concat([ciphertext, tag]);

  const license = {
    license_id: request.license_id,
    product_id: request.product_id,
    hw_fingerprint: request.hw_fingerprint,
    issued_at: issuedAt,
    expires_at: expiresAt,
    features: ['sbom', 'policy'],
    aes_key: encodeBase64Url(key),
    aes_iv: encodeBase64Url(iv)
  } satisfies Record<string, unknown>;

  const canonical = JSON.stringify(canonicalize(license));
  const signature = encodeBase64Url(sign(null, Buffer.from(canonical, 'utf8'), privateKey));

  return {
    signature,
    license,
    payload: encodeBase64Url(payload)
  };
}

function createLicenseResponse(
  request: LicenseRequestPayload,
  secretPayload: Record<string, unknown>,
  issuedAt: string,
  expiresAt: string
) {
  const plaintext = Buffer.from(`${JSON.stringify(secretPayload)}\n`, 'utf8');
  return createLicenseResponseFromPlaintext(request, plaintext, issuedAt, expiresAt);
}

beforeAll(() => {
  const keyPair = generateKeyPairSync('ed25519');
  publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  privateKey = keyPair.privateKey;
});


describe('license-manager CLI primitives', () => {
  let environment: TestEnvironment;

  beforeEach(() => {
    environment = setupEnvironment();
  });

  afterEach(() => {
    environment.keytarStore.clear();
    environment.files.clear();
    environment.writeOptions.clear();
    environment.appendOptions.clear();
    environment.logs.length = 0;
  });

  it('generates a license request and writes output', async () => {
    const outputPath = path.resolve('artifacts/license-request.json');
    const payload = await createLicenseRequest({
      outputPath,
      dependencies: environment.dependencies,
      logger: (message) => environment.logs.push(`console:${message}`)
    });

    expect(payload.license_id).toBe('uuid-fixed');
    expect(payload.product_id).toBe('product-alpha');
    expect(payload.request_nonce).toBe(encodeBase64Url(Buffer.alloc(24, 0xaa)));
    expect(payload.requested_at).toBe('2024-06-01T12:00:00.000Z');
    expect(payload.hw_fingerprint).toMatch(/^[A-Za-z0-9_-]{43}$/u);

    const written = environment.files.get(outputPath);
    expect(written).toBeDefined();
    expect(JSON.parse(written ?? '{}')).toMatchObject({
      license_id: 'uuid-fixed',
      product_id: 'product-alpha'
    });

    const logEntries = readLicenseLogEntries(environment);
    expect(logEntries).toHaveLength(1);
    expect(logEntries[0]).toMatchObject({
      action: 'license.requested',
      status: 'generated',
      license_id: 'uuid-fixed'
    });
  });

  it('produces deterministic hardware fingerprints and detects tampering', async () => {
    const first = await createLicenseRequest({ dependencies: environment.dependencies });
    const second = await createLicenseRequest({ dependencies: environment.dependencies });
    expect(second.hw_fingerprint).toBe(first.hw_fingerprint);

    const tamperedHostnameEnv = {
      ...environment.dependencies,
      hostname: () => 'other-host'
    } satisfies Record<string, unknown>;
    const tampered = await createLicenseRequest({ dependencies: tamperedHostnameEnv });
    expect(tampered.hw_fingerprint).not.toBe(first.hw_fingerprint);

    const alteredSeedEnv = {
      ...environment.dependencies,
      env: {
        ...(environment.dependencies.env as Record<string, string>),
        LICENSE_HW_SEED: 'seed-456'
      }
    } satisfies Record<string, unknown>;
    const reseeded = await createLicenseRequest({ dependencies: alteredSeedEnv });
    expect(reseeded.hw_fingerprint).not.toBe(first.hw_fingerprint);
  });

  it('fails the request when output cannot be written', async () => {
    const failingEnv = {
      ...environment.dependencies,
      open: () => Promise.reject(new Error('disk full'))
    };

    await expect(
      createLicenseRequest({
        outputPath: 'artifacts/license-request.json',
        dependencies: failingEnv
      })
    ).rejects.toThrow('disk full');
  });

  it('persists JSON outputs atomically via temp rename', async () => {
    const outputPath = path.resolve('artifacts/license-request.json');
    const originalRandomUuid = environment.dependencies.randomUUID as () => string;
    environment.dependencies.randomUUID = () => 'temp-seed';
    const renameSpy = vi.spyOn(
      environment.dependencies as { rename: (source: string, target: string) => Promise<void> },
      'rename'
    );

    await createLicenseRequest({
      outputPath,
      dependencies: environment.dependencies
    });

    const safeUuid = 'temp-seed'.replace(/[^a-zA-Z0-9]/gu, '');
    const tempPath = `${outputPath}.${safeUuid}.tmp`;
    expect(renameSpy).toHaveBeenCalledWith(tempPath, outputPath);
    expect(environment.files.has(tempPath)).toBe(false);
    expect(environment.files.get(outputPath)).toContain('license_id');

    environment.dependencies.randomUUID = originalRandomUuid;
    renameSpy.mockRestore();
  });

  it('retains previous JSON when atomic rename fails', async () => {
    const outputPath = path.resolve('artifacts/license-request.json');
    environment.setFile(outputPath, '{"legacy":true}\n');
    const originalRandomUuid = environment.dependencies.randomUUID as () => string;
    environment.dependencies.randomUUID = () => 'temp-seed';
    environment.dependencies.rename = vi.fn(async () => {
      throw new Error('rename failed');
    });

    await expect(
      createLicenseRequest({
        outputPath,
        dependencies: environment.dependencies
      })
    ).rejects.toThrow('rename failed');

    expect(environment.files.get(outputPath)).toBe('{"legacy":true}\n');
    expect(environment.logs.some((entry) => entry.includes('.temp-seed.tmp->'))).toBe(false);

    environment.dependencies.randomUUID = originalRandomUuid;
  });

  it('ensures the license log directory uses 0700 permissions', async () => {
    await createLicenseRequest({ dependencies: environment.dependencies });

    expect(environment.mkdirMock).toHaveBeenCalledWith(
      path.join('/home/tester', '.config', 'otomatik-oss'),
      expect.objectContaining({ recursive: true, mode: 0o700 })
    );
  });

  it('repairs license log directory permissions when they are too permissive', async () => {
    const directoryPath = path.join('/home/tester', '.config', 'otomatik-oss');
    environment.setDirectory(directoryPath, 0o755);

    await createLicenseRequest({ dependencies: environment.dependencies });

    expect(environment.chmodMock).toHaveBeenCalledWith(directoryPath, 0o700);
  });

  it('rejects when the license log directory cannot be secured', async () => {
    const directoryPath = path.join('/home/tester', '.config', 'otomatik-oss');
    environment.setDirectory(directoryPath, 0o755);
    environment.dependencies.chmod = vi.fn(async () => Promise.resolve());
    const originalStat = environment.dependencies.stat as (path: string) => Promise<{ size: number; mode: number }>;
    environment.dependencies.stat = vi.fn(async (targetPath: string) => {
      if (targetPath === directoryPath) {
        return { size: 0, mode: 0o755 };
      }
      return originalStat(targetPath);
    });

    await expect(createLicenseRequest({ dependencies: environment.dependencies })).rejects.toThrow(
      'License log directory permissions must not grant group or world access.'
    );
  });

  it('skips strict log directory checks on Windows', async () => {
    const directoryPath = path.join('/home/tester', '.config', 'otomatik-oss');
    environment.setDirectory(directoryPath, 0o755);
    environment.dependencies.platform = () => 'win32';

    await createLicenseRequest({ dependencies: environment.dependencies });

    expect(environment.chmodMock).not.toHaveBeenCalledWith(directoryPath, expect.any(Number));
  });

  it('rejects when the log directory is a symlink on Windows-like platforms', async () => {
    const directoryPath = path.join('/home/tester', '.config', 'otomatik-oss');
    const originalPlatform = environment.dependencies.platform as () => string;
    const originalLstat = environment.dependencies.lstat as (
      targetPath: string
    ) => Promise<{ mode: number; size: number; isSymbolicLink: () => boolean; isDirectory: () => boolean; isFile: () => boolean }>;

    environment.dependencies.platform = () => 'win32';
    environment.dependencies.lstat = vi.fn(async (targetPath: string) => {
      if (targetPath === directoryPath) {
        return {
          mode: 0o700,
          size: 0,
          isSymbolicLink: () => true,
          isDirectory: () => false,
          isFile: () => false
        };
      }
      return originalLstat(targetPath);
    });

    await expect(createLicenseRequest({ dependencies: environment.dependencies })).rejects.toThrow(
      'License log directory must not be a symbolic link.'
    );

    environment.dependencies.platform = originalPlatform;
    environment.dependencies.lstat = originalLstat;
  });

  it('rotates the license log when exceeding the size threshold', async () => {
    const logPath = path.join('/home/tester', '.config', 'otomatik-oss', 'license.log');
    const oversized = 'x'.repeat(5 * 1024 * 1024);
    environment.setFile(logPath, oversized);
    environment.setFile(`${logPath}.1`, '{"action":"previous"}\n');

    await createLicenseRequest({ dependencies: environment.dependencies });

    expect(environment.files.get(`${logPath}.1`)).toBe(oversized);
    expect(environment.files.get(`${logPath}.2`)).toBe('{"action":"previous"}\n');
    const logEntries = readLicenseLogEntries(environment);
    expect(logEntries).toHaveLength(1);
    expect(logEntries[0]).toMatchObject({ action: 'license.requested' });
    const renameEvents = environment.logs.filter((entry) => entry.startsWith('rename:'));
    expect(renameEvents).toHaveLength(2);
  });

  it('writes license log files with 0600 permissions', async () => {
    const logPath = path.join('/home/tester', '.config', 'otomatik-oss', 'license.log');

    await createLicenseRequest({ dependencies: environment.dependencies });

    expect(environment.appendOptions.get(logPath)).toMatchObject({ encoding: 'utf8', mode: 0o600 });
    const stat = await (environment.dependencies.stat as (target: string) => Promise<{ mode: number }>)(logPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('rejects when the license log file is a symlink', async () => {
    const logPath = path.join('/home/tester', '.config', 'otomatik-oss', 'license.log');
    environment.setFile(logPath, '', { mode: 0o600, symlink: true });

    await expect(createLicenseRequest({ dependencies: environment.dependencies })).rejects.toThrow(
      'License log file must not be a symlink.'
    );
  });

  it('rejects when the license log file is world-readable', async () => {
    const logPath = path.join('/home/tester', '.config', 'otomatik-oss', 'license.log');
    environment.setFile(logPath, '', { mode: 0o644 });

    await expect(createLicenseRequest({ dependencies: environment.dependencies })).rejects.toThrow(
      'License log file permissions must not grant group or world access.'
    );
  });

  it('installs, validates and stores the license secret', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const canonical = JSON.stringify(canonicalize(response.license));
    expect(verify(null, Buffer.from(canonical, 'utf8'), publicKey, decodeBase64Url(response.signature))).toBe(true);

    const result = await installLicense({
      response,
      dependencies: environment.dependencies
    });

    expect(result.licenseId).toBe(request.license_id);
    expect(result.features).toEqual(['sbom', 'policy']);
    expect(result.secret.trim()).toBe('{"token":"secret-token"}');

    const logEntries = readLicenseLogEntries(environment);
    expect(logEntries).toHaveLength(2);
    const installEntry = logEntries[1];
    expect(installEntry).toMatchObject({
      action: 'license.installed',
      license_id: request.license_id,
      status: 'installed'
    });
    expect(JSON.stringify(installEntry)).not.toContain('secret-token');

    const storedRaw = environment.keytarStore.values().next().value as string | undefined;
    expect(storedRaw).toBeDefined();
    const stored = JSON.parse(storedRaw ?? '{}') as Record<string, unknown>;
    expect(stored.license).toMatchObject({ license_id: request.license_id });
    expect(stored.secret).toBeDefined();
    const sealed = stored.secret as Record<string, string>;
    expect(sealed.algorithm).toBe('AES-256-GCM');
    expect(sealed.info).toBe('alterra-license-secret-v1');
    expect(typeof sealed.salt).toBe('string');
    expect(typeof sealed.nonce).toBe('string');
    expect(typeof sealed.ciphertext).toBe('string');
    expect(typeof sealed.tag).toBe('string');

    const salt = decodeBase64Url(sealed.salt);
    const nonce = decodeBase64Url(sealed.nonce);
    const ciphertext = decodeBase64Url(sealed.ciphertext);
    const tag = decodeBase64Url(sealed.tag);
    expect(salt.length).toBe(32);
    expect(nonce.length).toBe(12);
    expect(tag.length).toBe(16);

    const signatureBytes = decodeBase64Url(stored.signature as string);
    const fingerprint = request.hw_fingerprint;
    const decryptWith = (sig: Buffer, fp: string) => {
      const key = hkdfSync('sha256', Buffer.concat([sig, Buffer.from(fp, 'utf8')]), salt, 'alterra-license-secret-v1', 32);
      const decipher = createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plaintext.toString('utf8');
    };

    expect(decryptWith(signatureBytes, fingerprint).trim()).toBe('{"token":"secret-token"}');

    expect(() => decryptWith(signatureBytes, `${fingerprint}-tampered`)).toThrow();
    const mutatedSignature = Buffer.from(signatureBytes);
    mutatedSignature[0] ^= 0xff;
    expect(() => decryptWith(mutatedSignature, fingerprint)).toThrow();
  });

  it('installs a license with an empty decrypted secret', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponseFromPlaintext(
      request,
      Buffer.alloc(0),
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const canonical = JSON.stringify(canonicalize(response.license));
    expect(verify(null, Buffer.from(canonical, 'utf8'), publicKey, decodeBase64Url(response.signature))).toBe(true);

    const result = await installLicense({
      response,
      dependencies: environment.dependencies
    });

    expect(result.secret).toBe('');
  });

  it('rejects license installation when signature mismatches', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const signatureBytes = decodeBase64Url(response.signature);
    signatureBytes[0] ^= 0x01;
    const tampered = { ...response, signature: encodeBase64Url(signatureBytes) };

    await expect(
      installLicense({
        response: tampered,
        dependencies: environment.dependencies
      })
    ).rejects.toThrow('License signature verification failed');
  });

  it('rejects license payloads with malformed base64url material before decrypting', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const baseResponse = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const invalidCharsLicense = { ...baseResponse.license, aes_key: '@@' } as Record<string, unknown>;
    const invalidCharsSignature = encodeBase64Url(
      sign(null, Buffer.from(JSON.stringify(canonicalize(invalidCharsLicense)), 'utf8'), privateKey)
    );
    const invalidCharsResponse = {
      ...baseResponse,
      license: invalidCharsLicense,
      signature: invalidCharsSignature
    } as typeof baseResponse;

    await expect(
      installLicense({ response: invalidCharsResponse, dependencies: environment.dependencies })
    ).rejects.toThrow(/canonical base64url/i);

    const paddedResponse = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );
    const paddedLicense = { ...paddedResponse.license, aes_key: 'Zm8=' } as Record<string, unknown>;
    const paddedSignature = encodeBase64Url(
      sign(null, Buffer.from(JSON.stringify(canonicalize(paddedLicense)), 'utf8'), privateKey)
    );
    const nonCanonicalResponse = {
      ...paddedResponse,
      license: paddedLicense,
      signature: paddedSignature
    } as typeof paddedResponse;

    await expect(
      installLicense({ response: nonCanonicalResponse, dependencies: environment.dependencies })
    ).rejects.toThrow(/canonical base64url/i);
  });

  it('validates AES key and IV lengths before attempting payload decryption', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const baseResponse = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const shortKeyLicense = {
      ...baseResponse.license,
      aes_key: encodeBase64Url(Buffer.alloc(31, 0x11))
    } as Record<string, unknown>;
    const shortKeySignature = encodeBase64Url(
      sign(null, Buffer.from(JSON.stringify(canonicalize(shortKeyLicense)), 'utf8'), privateKey)
    );
    const shortKeyResponse = {
      ...baseResponse,
      license: shortKeyLicense,
      signature: shortKeySignature
    } as typeof baseResponse;

    await expect(
      installLicense({ response: shortKeyResponse, dependencies: environment.dependencies })
    ).rejects.toThrow('License AES key must be 32 bytes.');

    const longKeyLicense = {
      ...baseResponse.license,
      aes_key: encodeBase64Url(Buffer.alloc(33, 0x22))
    } as Record<string, unknown>;
    const longKeySignature = encodeBase64Url(
      sign(null, Buffer.from(JSON.stringify(canonicalize(longKeyLicense)), 'utf8'), privateKey)
    );
    const longKeyResponse = {
      ...baseResponse,
      license: longKeyLicense,
      signature: longKeySignature
    } as typeof baseResponse;

    await expect(
      installLicense({ response: longKeyResponse, dependencies: environment.dependencies })
    ).rejects.toThrow('License AES key must be 32 bytes.');

    const baseResponseForIv = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );
    const invalidIvLicense = {
      ...baseResponseForIv.license,
      aes_iv: encodeBase64Url(Buffer.alloc(10, 0x22))
    } as Record<string, unknown>;
    const invalidIvSignature = encodeBase64Url(
      sign(null, Buffer.from(JSON.stringify(canonicalize(invalidIvLicense)), 'utf8'), privateKey)
    );
    const invalidIvResponse = {
      ...baseResponseForIv,
      license: invalidIvLicense,
      signature: invalidIvSignature
    } as typeof baseResponseForIv;

    await expect(
      installLicense({ response: invalidIvResponse, dependencies: environment.dependencies })
    ).rejects.toThrow('License AES IV must be 12 bytes.');

    const longIvLicense = {
      ...baseResponseForIv.license,
      aes_iv: encodeBase64Url(Buffer.alloc(16, 0x33))
    } as Record<string, unknown>;
    const longIvSignature = encodeBase64Url(
      sign(null, Buffer.from(JSON.stringify(canonicalize(longIvLicense)), 'utf8'), privateKey)
    );
    const longIvResponse = {
      ...baseResponseForIv,
      license: longIvLicense,
      signature: longIvSignature
    } as typeof baseResponseForIv;

    await expect(
      installLicense({ response: longIvResponse, dependencies: environment.dependencies })
    ).rejects.toThrow('License AES IV must be 12 bytes.');
    expect(environment.keytarStore.size).toBe(0);
  });

  it('reports license status and updates validation timestamp', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const canonical = JSON.stringify(canonicalize(response.license));
    expect(verify(null, Buffer.from(canonical, 'utf8'), publicKey, decodeBase64Url(response.signature))).toBe(true);

    await installLicense({ response, dependencies: environment.dependencies });
    environment.setNow(new Date('2024-07-01T00:00:00.000Z'));

    const status = await getLicenseStatus({ dependencies: environment.dependencies });

    expect(status.status).toBe('active');
    expect(status.warnings).toEqual([]);
    expect(status.lastValidatedAt).toBe('2024-07-01T00:00:00.000Z');

    const logEntries = readLicenseLogEntries(environment);
    expect(logEntries).toHaveLength(3);
    const statusEntry = logEntries[2];
    expect(statusEntry).toMatchObject({
      action: 'license.status_checked',
      license_id: request.license_id,
      status: 'active'
    });

    const storedRaw = environment.keytarStore.values().next().value as string | undefined;
    const stored = JSON.parse(storedRaw ?? '{}') as Record<string, unknown>;
    expect(stored.last_validated_at).toBe('2024-07-01T00:00:00.000Z');
  });

  it('fails status check when no license installed', async () => {
    await expect(
      getLicenseStatus({ dependencies: environment.dependencies })
    ).rejects.toThrow('No license is currently installed');
  });

  it('purges corrupted stored license data before failing status check', async () => {
    environment.keytarStore.set(
      'otomatik-oss-license:primary',
      JSON.stringify({
        signature: 'invalid',
        secret: 'value',
        installed_at: '2024-06-01T12:00:00.000Z',
        last_validated_at: '2024-06-01T12:00:00.000Z'
      })
    );

    await expect(
      getLicenseStatus({ dependencies: environment.dependencies })
    ).rejects.toThrow(/Stored license data is invalid/);
    expect(environment.keytarStore.size).toBe(0);

    const logEntries = readLicenseLogEntries(environment);
    expect(logEntries).toHaveLength(2);
    expect(logEntries[0]).toMatchObject({
      action: 'license.corrupted_purged',
      status: 'purged'
    });
    expect((logEntries[0].metadata as { reason?: string } | undefined)?.reason).toContain(
      'Stored license data is invalid'
    );
    expect(logEntries[1]).toMatchObject({ action: 'license.status_failed', status: 'failed' });
  });

  it('logs sanitized failure entries when installation rejects', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const tampered = {
      ...response,
      license: { ...response.license, product_id: 'otomatik-oss-suite-enterprise' }
    } as typeof response;

    await expect(
      installLicense({ response: tampered, dependencies: environment.dependencies })
    ).rejects.toThrow(/product_id/i);

    const logEntries = readLicenseLogEntries(environment);
    const failureEntry = logEntries.at(-1) as Record<string, unknown>;
    expect(failureEntry).toMatchObject({
      action: 'license.install_failed',
      license_id: request.license_id,
      status: 'failed'
    });
    const metadata = (failureEntry.metadata ?? {}) as Record<string, unknown>;
    expect(String(metadata.reason)).toMatch(/product_id/i);
    expect(JSON.stringify(failureEntry)).not.toContain('secret-token');
  });

  it('logs sanitized failure entries when status validation rejects', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    await installLicense({ response, dependencies: environment.dependencies });

    const storageKey = 'otomatik-oss-license:primary';
    const storedRaw = environment.keytarStore.get(storageKey);
    expect(storedRaw).toBeDefined();
    if (!storedRaw) {
      throw new Error('Stored license not found in test environment.');
    }
    const stored = JSON.parse(storedRaw) as Record<string, unknown>;
    const storedLicense = stored.license as Record<string, unknown>;
    storedLicense.hw_fingerprint = 'tampered-fingerprint';
    environment.keytarStore.set(storageKey, JSON.stringify(stored));

    await expect(
      getLicenseStatus({ dependencies: environment.dependencies })
    ).rejects.toThrow(/belong to this node/i);

    const logEntries = readLicenseLogEntries(environment);
    const failureEntry = logEntries.at(-1) as Record<string, unknown>;
    expect(failureEntry).toMatchObject({
      action: 'license.status_failed',
      license_id: request.license_id,
      status: 'failed'
    });
    const metadata = (failureEntry.metadata ?? {}) as Record<string, unknown>;
    expect(String(metadata.reason)).toMatch(/belong/i);
    expect(JSON.stringify(failureEntry)).not.toContain('secret-token');
  });

  it('purges license secrets from secure storage', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const canonical = JSON.stringify(canonicalize(response.license));
    expect(verify(null, Buffer.from(canonical, 'utf8'), publicKey, decodeBase64Url(response.signature))).toBe(true);
    await installLicense({ response, dependencies: environment.dependencies });

    await purgeLicense({ dependencies: environment.dependencies });

    expect(environment.keytarStore.size).toBe(0);

    const logEntries = readLicenseLogEntries(environment);
    expect(logEntries.at(-1)).toMatchObject({
      action: 'license.purged',
      status: 'purged'
    });
  });

  it('fails purge when storage is already empty', async () => {
    await expect(
      purgeLicense({ dependencies: environment.dependencies })
    ).rejects.toThrow('No license data found to purge');
  });

  it('refuses CLI install until the EULA is accepted', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const responsePath = path.resolve('artifacts/cli-response.json');
    environment.setFile(responsePath, JSON.stringify(response));

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(
      licenseManagerCli(['install', '--response', responsePath], environment.dependencies as never)
    ).rejects.toThrow('EULA acceptance is required');
    stdoutSpy.mockRestore();
  });

  it('persists EULA acceptance and reuses stored consent on subsequent commands', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const responsePath = path.resolve('artifacts/cli-response.json');
    environment.setFile(responsePath, JSON.stringify(response));

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(
      licenseManagerCli(['install', '--response', responsePath, '--accept-eula'], environment.dependencies as never)
    ).resolves.toBeUndefined();
    stdoutSpy.mockRestore();

    const eulaPath = path.join('/home/tester', '.config', 'otomatik-oss', 'eula.json');
    const eulaRaw = environment.files.get(eulaPath);
    expect(eulaRaw).toBeDefined();
    const eula = JSON.parse(eulaRaw ?? '{}') as Record<string, unknown>;
    expect(eula.version).toBe('2024.06');
    const eulaStat = await (environment.dependencies.stat as (target: string) => Promise<{ mode: number }>)(
      eulaPath
    );
    expect(eulaStat.mode & 0o777).toBe(0o600);

    const secondSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(licenseManagerCli(['status'], environment.dependencies as never)).resolves.toBeUndefined();
    secondSpy.mockRestore();
  });

  it('rejects mismatched EULA version overrides until the current version is provided', async () => {
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const responsePath = path.resolve('artifacts/cli-response.json');
    environment.setFile(responsePath, JSON.stringify(response));

    const eulaPath = path.join('/home/tester', '.config', 'otomatik-oss', 'eula.json');

    const failureSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(
      licenseManagerCli(
        ['install', '--response', responsePath, '--accept-eula=2023.01'],
        environment.dependencies as never
      )
    ).rejects.toThrow('EULA acceptance requires version 2024.06');
    failureSpy.mockRestore();

    expect(environment.files.has(eulaPath)).toBe(false);

    const successSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(
      licenseManagerCli(['install', '--response', responsePath, '--accept-eula'], environment.dependencies as never)
    ).resolves.toBeUndefined();
    successSpy.mockRestore();

    const marker = environment.files.get(eulaPath);
    expect(marker).toBeDefined();
    const parsed = JSON.parse(marker ?? '{}') as Record<string, unknown>;
    expect(parsed.version).toBe('2024.06');
  });

  it('writes the macOS system acceptance marker when the EULA is accepted', async () => {
    environment.dependencies.platform = () => 'darwin';
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const responsePath = path.resolve('artifacts/mac-cli-response.json');
    environment.setFile(responsePath, JSON.stringify(response));

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(
      licenseManagerCli(['install', '--response', responsePath, '--accept-eula'], environment.dependencies as never)
    ).resolves.toBeUndefined();
    stdoutSpy.mockRestore();

    const systemDirectory = path.posix.join('/Library/Application Support', 'Atlas SCA');
    const systemMarkerPath = path.posix.join(systemDirectory, 'eula.accepted');
    expect(environment.files.has(systemMarkerPath)).toBe(true);
    const writeOptions = environment.writeOptions.get(systemMarkerPath) as { mode?: number } | undefined;
    expect(writeOptions).toMatchObject({ mode: 0o600 });
    expect(environment.mkdirMock).toHaveBeenCalledWith(
      systemDirectory,
      expect.objectContaining({ recursive: true, mode: 0o700 })
    );
  });

  it('writes the Windows system acceptance marker when the EULA is accepted', async () => {
    environment.dependencies.platform = () => 'win32';
    (environment.dependencies.env as Record<string, string | undefined>).PROGRAMDATA = 'D\\\\ProgramData';
    const request = await createLicenseRequest({ dependencies: environment.dependencies });
    const response = createLicenseResponse(
      request,
      { token: 'secret-token' },
      '2024-05-30T00:00:00.000Z',
      '2024-12-31T23:59:59.000Z'
    );

    const responsePath = path.resolve('artifacts/win-cli-response.json');
    environment.setFile(responsePath, JSON.stringify(response));

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await expect(
      licenseManagerCli(['install', '--response', responsePath, '--accept-eula'], environment.dependencies as never)
    ).resolves.toBeUndefined();
    stdoutSpy.mockRestore();

    const systemDirectory = path.win32.join('D:\\ProgramData', 'Atlas SCA');
    const systemMarkerPath = path.win32.join(systemDirectory, 'eula.accepted');
    expect(environment.files.has(systemMarkerPath)).toBe(true);
    const writeOptions = environment.writeOptions.get(systemMarkerPath) as { mode?: number } | undefined;
    expect(writeOptions).toMatchObject({ mode: 0o600 });
  });
});
