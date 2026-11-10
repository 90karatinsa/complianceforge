// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import path from 'node:path';

import { recordUpdateLogEntry } from '../observability/update-log.ts';

describe('update log metadata scrubbing', () => {
  it('masks only keys that begin or end with sensitive tokens', async () => {
    const writes: string[] = [];

    const appendFile = vi.fn(async (_path: string, data: string, options?: { mode?: number }) => {
      expect(options).toMatchObject({ mode: 0o600 });
      writes.push(data.trim());
    });

    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile,
      rename: vi.fn(() => Promise.resolve()),
      rm: vi.fn(() => Promise.resolve()),
      chmod: vi.fn(() => Promise.resolve()),
      lstat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      stat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile: vi.fn(() => Promise.resolve()),
      homedir: () => '/tmp'
    } as const;

    await recordUpdateLogEntry(
      {
        action: 'feed.activate',
        manifest_id: 'manifest-1',
        version: '2024.07',
        actor: 'api_key:test',
        result: 'success',
        metadata: {
          api_key: 'should hide',
          clientSecret: 'should hide',
          monkey: 'bananas',
          prefix_secret: 'hide me',
          token_suffix: 'hide me',
          nested: {
            access_token: 'hide me',
            label: 'visible'
          }
        }
      },
      { dependencies }
    );

    expect(appendFile).toHaveBeenCalledTimes(1);
    const serialized = writes[0];
    expect(typeof serialized).toBe('string');

    const parsed = JSON.parse(serialized ?? '{}') as Record<string, unknown>;
    const metadata = parsed.metadata as Record<string, unknown>;

    expect(metadata.api_key).toBe('***');
    expect(metadata.clientSecret).toBe('***');
    expect(metadata.prefix_secret).toBe('***');
    expect(metadata.token_suffix).toBe('***');
    expect(metadata.monkey).toBe('bananas');

    const nested = metadata.nested as Record<string, unknown>;
    expect(nested.access_token).toBe('***');
    expect(nested.label).toBe('visible');
  });

  it('rotates logs with restrictive file permissions', async () => {
    const logPath = '/tmp/.config/otomatik-oss/updates.log';
    const appendFile = vi.fn(async () => Promise.resolve());
    const writeFile = vi.fn(async () => Promise.resolve());
    const rename = vi.fn(async () => Promise.resolve());

    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile,
      rename,
      rm: vi.fn(() => Promise.resolve()),
      chmod: vi.fn(() => Promise.resolve()),
      lstat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      stat: vi
        .fn()
        .mockResolvedValueOnce({ size: 6 * 1024 * 1024 })
        .mockImplementation(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile,
      homedir: () => '/tmp'
    } as const;

    await recordUpdateLogEntry(
      {
        action: 'feed.activate',
        manifest_id: 'manifest-1',
        version: '2024.07',
        actor: 'api',
        result: 'success'
      },
      { dependencies }
    );

    expect(writeFile).toHaveBeenCalledWith(logPath, '', { encoding: 'utf8', mode: 0o600 });
    expect(appendFile).toHaveBeenCalledWith(logPath, expect.any(String), {
      encoding: 'utf8',
      mode: 0o600
    });
    expect(rename).toHaveBeenCalled();
  });

  it('deletes pre-existing backups before renaming to avoid EEXIST on Windows', async () => {
    const directoryPath = path.join('/tmp', '.config', 'otomatik-oss');
    const logPath = path.join(directoryPath, 'updates.log');
    const rm = vi.fn(async () => Promise.resolve());
    const rename = vi.fn(async () => Promise.resolve());
    const writeFile = vi.fn(async () => Promise.resolve());

    const lstat = vi.fn(async (target: string) => {
      if (target === directoryPath) {
        return { mode: 0o700, isSymbolicLink: () => false, isDirectory: () => true };
      }
      if (target === logPath) {
        return { mode: 0o600, isSymbolicLink: () => false, isFile: () => true };
      }
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });

    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile: vi.fn(async () => Promise.resolve()),
      rename,
      rm,
      chmod: vi.fn(() => Promise.resolve()),
      lstat,
      stat: vi
        .fn()
        .mockResolvedValueOnce({ size: 6 * 1024 * 1024 })
        .mockImplementation(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile,
      homedir: () => '/tmp'
    } as const;

    await recordUpdateLogEntry(
      {
        action: 'feed.activate',
        manifest_id: 'manifest-1',
        version: '2024.07',
        actor: 'api',
        result: 'success'
      },
      { dependencies }
    );

    const expectedTargets = [`${logPath}.2`, `${logPath}.1`];
    expect(rm.mock.calls.map((call) => call[0])).toEqual(expectedTargets);
    expect(rename.mock.calls.map((call) => call[1])).toEqual(expectedTargets);
    expect(writeFile).toHaveBeenCalledWith(logPath, '', { encoding: 'utf8', mode: 0o600 });
    rm.mock.calls.forEach((_, index) => {
      expect(rm.mock.invocationCallOrder[index]).toBeLessThan(rename.mock.invocationCallOrder[index]);
    });
  });

  it('repairs insecure update log directory permissions before writing', async () => {
    const appendFile = vi.fn(async () => Promise.resolve());
    const chmod = vi.fn(async () => Promise.resolve());
    const directoryPath = path.join('/tmp', '.config', 'otomatik-oss');
    const logPath = path.join(directoryPath, 'updates.log');
    let firstDirectoryCheck = true;
    const lstat = vi.fn(async (target: string) => {
      if (target === directoryPath) {
        if (firstDirectoryCheck) {
          firstDirectoryCheck = false;
          return { mode: 0o755, isSymbolicLink: () => false, isDirectory: () => true };
        }
        return { mode: 0o700, isSymbolicLink: () => false, isDirectory: () => true };
      }
      if (target === logPath) {
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      }
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });

    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile,
      rename: vi.fn(() => Promise.resolve()),
      rm: vi.fn(() => Promise.resolve()),
      chmod,
      lstat,
      stat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile: vi.fn(() => Promise.resolve()),
      homedir: () => '/tmp',
      platform: () => 'linux'
    } as const;

    await recordUpdateLogEntry(
      {
        action: 'feed.activate',
        manifest_id: 'manifest-1',
        version: '2024.07',
        actor: 'api',
        result: 'success'
      },
      { dependencies }
    );

    expect(chmod).toHaveBeenCalledWith(path.join('/tmp', '.config', 'otomatik-oss'), 0o700);
  });

  it('rejects symlinked update log directories', async () => {
    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile: vi.fn(),
      rename: vi.fn(() => Promise.resolve()),
      rm: vi.fn(() => Promise.resolve()),
      chmod: vi.fn(() => Promise.resolve()),
      lstat: vi.fn(() => ({ mode: 0o777, isSymbolicLink: () => true, isDirectory: () => false })),
      stat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile: vi.fn(() => Promise.resolve()),
      homedir: () => '/tmp'
    } as const;

    await expect(
      recordUpdateLogEntry(
        {
          action: 'feed.activate',
          manifest_id: 'manifest-1',
          version: '2024.07',
          actor: 'api',
          result: 'success'
        },
        { dependencies }
      )
    ).rejects.toThrow('Update log directory must not be a symbolic link.');
  });

  it('rejects symlinked update log files', async () => {
    const directoryPath = path.join('/tmp', '.config', 'otomatik-oss');
    const logPath = path.join(directoryPath, 'updates.log');

    const lstat = vi.fn(async (target: string) => {
      if (target === directoryPath) {
        return { mode: 0o700, isSymbolicLink: () => false, isDirectory: () => true };
      }
      if (target === logPath) {
        return { mode: 0o600, isSymbolicLink: () => true, isFile: () => false };
      }
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });

    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile: vi.fn(),
      rename: vi.fn(() => Promise.resolve()),
      rm: vi.fn(() => Promise.resolve()),
      chmod: vi.fn(() => Promise.resolve()),
      lstat,
      stat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile: vi.fn(() => Promise.resolve()),
      homedir: () => '/tmp',
      platform: () => 'linux'
    } as const;

    await expect(
      recordUpdateLogEntry(
        {
          action: 'feed.activate',
          manifest_id: 'manifest-1',
          version: '2024.07',
          actor: 'api',
          result: 'success'
        },
        { dependencies }
      )
    ).rejects.toThrow('Update log file must not be a symlink.');
  });

  it('repairs insecure update log file permissions before writing', async () => {
    const directoryPath = path.join('/tmp', '.config', 'otomatik-oss');
    const logPath = path.join(directoryPath, 'updates.log');
    let firstFileCheck = true;

    const lstat = vi.fn(async (target: string) => {
      if (target === directoryPath) {
        return { mode: 0o700, isSymbolicLink: () => false, isDirectory: () => true };
      }
      if (target === logPath) {
        if (firstFileCheck) {
          firstFileCheck = false;
          return { mode: 0o644, isSymbolicLink: () => false, isFile: () => true };
        }
        return { mode: 0o600, isSymbolicLink: () => false, isFile: () => true };
      }
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });

    const chmod = vi.fn(async () => Promise.resolve());
    const appendFile = vi.fn(async () => Promise.resolve());

    const dependencies = {
      now: () => new Date('2024-07-01T00:00:00.000Z'),
      mkdir: vi.fn(() => Promise.resolve()),
      appendFile,
      rename: vi.fn(() => Promise.resolve()),
      rm: vi.fn(() => Promise.resolve()),
      chmod,
      lstat,
      stat: vi.fn(() => Promise.reject(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))),
      writeFile: vi.fn(() => Promise.resolve()),
      homedir: () => '/tmp',
      platform: () => 'linux'
    } as const;

    await recordUpdateLogEntry(
      {
        action: 'feed.activate',
        manifest_id: 'manifest-1',
        version: '2024.07',
        actor: 'api',
        result: 'success'
      },
      { dependencies }
    );

    expect(chmod).toHaveBeenCalledWith(logPath, 0o600);
    expect(appendFile).toHaveBeenCalledTimes(1);
  });
});
