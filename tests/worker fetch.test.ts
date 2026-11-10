// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import type { PrivateAddressError } from '../worker/src/fetcher';

const execFileMock = vi.fn(
  (
    _command: string,
    _args: string[],
    _options: Record<string, unknown>,
    callback?: (error: Error | null, stdout?: string, stderr?: string) => void
  ) => {
    callback?.(null, '', '');
  }
);

interface FileHandleStub {
  write: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  writes: Uint8Array[];
}

const openHandles: FileHandleStub[] = [];

const fsMock = {
  rm: vi.fn(() => Promise.resolve(undefined)),
  mkdir: vi.fn(() => Promise.resolve(undefined)),
  writeFile: vi.fn(() => Promise.resolve(undefined)),
  open: vi.fn(async () => {
    const handle: FileHandleStub = {
      writes: [],
      write: vi.fn(async (chunk: Uint8Array) => {
        const buffer = chunk instanceof Uint8Array ? new Uint8Array(chunk) : new Uint8Array(chunk);
        handle.writes.push(buffer);
        return { bytesWritten: buffer.length, buffer };
      }),
      close: vi.fn(async () => {})
    };

    openHandles.push(handle);
    return handle as unknown as import('node:fs/promises').FileHandle;
  })
};

vi.mock('node:child_process', () => ({
  execFile: execFileMock
}));

vi.mock('node:fs/promises', () => fsMock);

const lookupMockImpl = vi.fn(() => Promise.resolve([{ address: '198.51.100.10', family: 4 }]));
const lookupMock = lookupMockImpl as unknown as typeof import('node:dns/promises').lookup;

vi.mock('node:dns/promises', () => ({
  lookup: lookupMock
}));

type LookupFn = (
  hostname: string,
  options: { family?: number; hints?: number; all?: boolean },
  callback: (error: PrivateAddressError | null, address?: string, family?: number) => void
) => void;

interface AgentInstance {
  options: { connect?: { lookup?: LookupFn } };
  dispatch: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  destroy: ReturnType<typeof vi.fn>;
}

const agentMock = vi.fn((options: { connect?: { lookup?: LookupFn } }) => {
  const instance: AgentInstance = {
    options,
    dispatch: vi.fn(),
    close: vi.fn(() => Promise.resolve()),
    destroy: vi.fn(() => Promise.resolve())
  };
  return instance;
});

vi.mock('undici', () => ({
  Agent: agentMock
}));

function loadFetcher(): Promise<typeof import('../worker/src/fetcher.ts')> {
  return import('../worker/src/fetcher.ts');
}

function loadFetcherWithNetwork(): Promise<typeof import('../worker/src/fetcher.ts')> {
  process.env.ALLOW_NETWORK_FETCH = 'true';
  return loadFetcher();
}

function createStream(chunks: Array<string | Uint8Array> | null): unknown {
  type MockReaderResult = Promise<{ value?: Uint8Array; done: boolean }>;
  type MockStreamReader = {
    read(): MockReaderResult;
    cancel(reason?: unknown): Promise<void>;
  };
  type MockStream = {
    getReader(): MockStreamReader;
  };

  if (chunks === null) {
    return undefined;
  }

  let index = 0;
  let cancelled = false;
  const encoder = new TextEncoder();

  const stream: MockStream = {
    getReader() {
      return {
        async read() {
          if (cancelled || !chunks || index >= chunks.length) {
            return { value: undefined, done: true };
          }

          const chunk = chunks[index++];
          const value = typeof chunk === 'string' ? encoder.encode(chunk) : chunk;
          return { value, done: false };
        },
        async cancel() {
          cancelled = true;
        }
      };
    }
  };

  return stream;
}

function createMockResponse(options: {
  status?: number;
  ok?: boolean;
  headers?: Record<string, string>;
  bodyChunks?: Array<string | Uint8Array> | null;
  bodyStream?: unknown;
  jsonBody?: unknown;
  textBody?: string;
}): Response {
  const {
    status = 200,
    ok = true,
    headers = {},
    bodyChunks = [],
    bodyStream,
    jsonBody,
    textBody = ''
  } = options;

  const headerMap = new Map<string, string>();
  for (const [key, value] of Object.entries(headers)) {
    headerMap.set(key.toLowerCase(), value);
  }

  const body = bodyStream ?? createStream(bodyChunks);

  return {
    ok,
    status,
    headers: {
      get(name: string): string | null {
        return headerMap.get(name.toLowerCase()) ?? null;
      }
    } as Headers,
    body,
    async json(): Promise<unknown> {
      return jsonBody ?? {};
    },
    async text(): Promise<string> {
      return textBody;
    }
  } as unknown as Response;
}

describe('worker fetch', () => {
  const envKeys = ['ALLOW_NETWORK_FETCH', 'GIT_BIN', 'TAR_BIN', 'UNZIP_BIN'] as const;
  let envSnapshot: Record<(typeof envKeys)[number], string | undefined>;

  beforeEach(() => {
    execFileMock.mockClear();
    execFileMock.mockImplementation((
      _command: string,
      _args: string[],
      _options: Record<string, unknown>,
      callback?: (error: Error | null, stdout?: string, stderr?: string) => void
    ) => {
      callback?.(null, '', '');
    });
    fsMock.rm.mockClear();
    fsMock.mkdir.mockClear();
    fsMock.writeFile.mockClear();
    fsMock.open.mockClear();
    openHandles.length = 0;
    lookupMockImpl.mockReset();
    lookupMockImpl.mockResolvedValue([{ address: '198.51.100.10', family: 4 }]);
    agentMock.mockClear();
    envSnapshot = {} as Record<(typeof envKeys)[number], string | undefined>;

    for (const key of envKeys) {
      envSnapshot[key] = process.env[key];
      delete process.env[key];
    }

    vi.resetModules();
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (envSnapshot[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = envSnapshot[key];
      }
    }

    vi.useRealTimers();
  });

  it('fetches git artifacts into a deterministic workspace', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const result = await fetcher.fetchArtifact({
      scanId: 'scan-git',
      artifact: {
        type: 'git',
        ref: { url: 'https://example.com/repo.git', branch: 'main' }
      }
    });

    const workspacePath = fetcher.resolveWorkspacePath('scan-git');
    expect(fsMock.rm).toHaveBeenCalledWith(workspacePath, { recursive: true, force: true });
    expect(fsMock.mkdir).toHaveBeenCalledWith(workspacePath, { recursive: true });
    const execCall = execFileMock.mock.calls[0];
    expect(execCall?.[0]).toBe('git');
    expect(execCall?.[1]).toEqual([
      '-c',
      'http.followRedirects=false',
      'clone',
      '--depth',
      '1',
      '--no-tags',
      '--branch',
      'main',
      '--',
      'https://example.com/repo.git',
      join(workspacePath, 'source')
    ]);
    expect(typeof (execCall?.[2] as { timeout?: unknown })?.timeout).toBe('number');
    expect(result).toEqual({
      workspacePath,
      artifactPath: join(workspacePath, 'source')
    });
  });

  it('allows git artifacts over SSH', async () => {
    const fetcher = await loadFetcherWithNetwork();

    await fetcher.fetchArtifact({
      scanId: 'scan-git-ssh',
      artifact: {
        type: 'git',
        ref: { url: 'ssh://example.com/repo.git' }
      }
    });

    const workspacePath = fetcher.resolveWorkspacePath('scan-git-ssh');
    const execCall = execFileMock.mock.calls[0];
    expect(execCall?.[1]).toEqual([
      '-c',
      'http.followRedirects=false',
      'clone',
      '--depth',
      '1',
      '--no-tags',
      '--',
      'ssh://example.com/repo.git',
      join(workspacePath, 'source')
    ]);
  });

  it('rejects git artifacts that are not HTTPS or SSH', async () => {
    const fetcher = await loadFetcherWithNetwork();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-http',
        artifact: {
          type: 'git',
          ref: { url: 'http://example.com/repo.git' }
        }
      })
    ).rejects.toThrow(/HTTPS or SSH/);
  });

  it('rejects git fetches when ALLOW_NETWORK_FETCH is disabled', async () => {
    process.env.ALLOW_NETWORK_FETCH = 'false';
    const fetcher = await loadFetcher();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-disabled',
        artifact: {
          type: 'git',
          ref: { url: 'https://example.com/repo.git' }
        }
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('rejects git fetches when ALLOW_NETWORK_FETCH is unset', async () => {
    const fetcher = await loadFetcher();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-unset',
        artifact: {
          type: 'git',
          ref: { url: 'https://example.com/repo.git' }
        }
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('surfaces redirect errors from git clone with a descriptive message', async () => {
    const redirectError = Object.assign(new Error('fatal: HTTP redirect to https://mirror.example/repo.git'), {
      stderr: 'fatal: HTTP redirect to https://mirror.example/repo.git'
    });
    execFileMock.mockImplementationOnce(
      (
        _command: string,
        _args: string[],
        _options: Record<string, unknown>,
        callback?: (error: Error | null) => void
      ) => {
        callback?.(redirectError);
      }
    );

    const fetcher = await loadFetcherWithNetwork();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-redirect',
        artifact: {
          type: 'git',
          ref: { url: 'https://example.com/repo.git' }
        }
      })
    ).rejects.toThrow(/remote attempted an HTTP redirect/);

    expect(execFileMock).toHaveBeenCalledTimes(1);
  });

  it('rejects git HTTPS artifacts that resolve to private addresses', async () => {
    lookupMockImpl.mockResolvedValue([{ address: '10.0.0.5', family: 4 }]);
    const fetcher = await loadFetcherWithNetwork();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-private-https',
        artifact: {
          type: 'git',
          ref: { url: 'https://internal.example.com/repo.git' }
        }
      })
    ).rejects.toThrow(/private address/);

    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('rejects git SSH artifacts targeting private hosts', async () => {
    lookupMockImpl.mockResolvedValue([{ address: '192.168.1.10', family: 4 }]);
    const fetcher = await loadFetcherWithNetwork();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-private-ssh',
        artifact: {
          type: 'git',
          ref: { url: 'ssh://internal.example.com/repo.git' }
        }
      })
    ).rejects.toThrow(/private address/);

    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('rejects git SSH artifacts using literal private IP addresses', async () => {
    const fetcher = await loadFetcherWithNetwork();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-private-ip',
        artifact: {
          type: 'git',
          ref: { url: 'ssh://192.168.1.50/repo.git' }
        }
      })
    ).rejects.toThrow(/private address/);

    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('rejects git artifacts targeting IPv4-mapped IPv6 private hosts', async () => {
    const fetcher = await loadFetcherWithNetwork();

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-git-ipv4-mapped-private',
        artifact: {
          type: 'git',
          ref: { url: 'https://[::ffff:10.0.0.5]/repo.git' }
        }
      })
    ).rejects.toThrow(/private address/);

    expect(execFileMock).not.toHaveBeenCalled();
    expect(lookupMockImpl).not.toHaveBeenCalled();
  });

  it('allows git artifacts targeting IPv4-mapped IPv6 public hosts', async () => {
    const fetcher = await loadFetcherWithNetwork();

    await fetcher.fetchArtifact({
      scanId: 'scan-git-ipv4-mapped-public',
      artifact: {
        type: 'git',
        ref: { url: 'https://[::ffff:203.0.113.50]/repo.git' }
      }
    });

    const execCall = execFileMock.mock.calls[0];
    expect(execCall?.[1]).toEqual(
      expect.arrayContaining([
        'clone',
        '--depth',
        '1',
        '--no-tags',
        '--',
        'https://[::ffff:203.0.113.50]/repo.git'
      ])
    );
  });

  it('rejects archive fetches when ALLOW_NETWORK_FETCH is disabled', async () => {
    process.env.ALLOW_NETWORK_FETCH = '0';
    const fetcher = await loadFetcher();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-disabled',
        artifact: {
          type: 'archive',
          ref: { url: 'https://example.com/bundle.zip' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('rejects archive URLs that are not HTTPS', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-http',
        artifact: {
          type: 'archive',
          ref: { url: 'http://example.com/archive.zip' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/must use HTTPS/);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('disables redirects when downloading archives', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({ status: 200 })));

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-redirect',
      artifact: {
        type: 'archive',
        ref: { url: 'https://example.com/bundle.tar' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    const call = fetchSpy.mock.calls[0];
    expect((call?.[1] as { redirect?: string } | undefined)?.redirect).toBe('manual');
  });

  it('rejects archive downloads when Content-Length exceeds the limit', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() =>
      Promise.resolve(
        createMockResponse({
          status: 200,
          headers: { 'content-length': String(209_715_200 + 1) }
        })
      )
    );

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-too-large',
        artifact: {
          type: 'archive',
          ref: { url: 'https://example.com/oversize.tar' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/declared size/);

    expect(fsMock.open).not.toHaveBeenCalled();
  });

  it('streams archive downloads into file handles', async () => {
    const fetcher = await loadFetcherWithNetwork();
    const encoder = new TextEncoder();
    const fetchSpy = vi.fn(() =>
      Promise.resolve(
        createMockResponse({
          status: 200,
          bodyChunks: [encoder.encode('chunk-a'), encoder.encode('chunk-b')]
        })
      )
    );

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-stream',
      artifact: {
        type: 'archive',
        ref: { url: 'https://example.com/archive.tar' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    expect(openHandles).toHaveLength(1);
    const writes = openHandles[0]?.writes ?? [];
    expect(writes).toHaveLength(2);
    const decoder = new TextDecoder();
    expect(decoder.decode(writes[0])).toBe('chunk-a');
    expect(decoder.decode(writes[1])).toBe('chunk-b');
  });

  it('rejects tar archives containing traversal entries before extraction', async () => {
    const fetcher = await loadFetcherWithNetwork();

    execFileMock.mockImplementation((command, args, _options, callback) => {
      if (args.includes('-tvf')) {
        callback?.(
          null,
          'lrw-r--r-- 0/0               0 1970-01-01 00:00 link -> ../outside\n',
          ''
        );
        return;
      }

      callback?.(null, '', '');
    });

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-tar-traversal',
        artifact: {
          type: 'archive',
          ref: { url: 'https://example.com/bundle.tar' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/unsafe symlink/);

    expect(execFileMock.mock.calls.some((call) => call[1].includes('--extract'))).toBe(false);
  });

  it('rejects zip archives containing symlinks before extraction', async () => {
    const fetcher = await loadFetcherWithNetwork();

    execFileMock.mockImplementation((command, args, _options, callback) => {
      if (args.includes('-Z') && args.includes('-l')) {
        callback?.(
          null,
          'Archive:  /tmp/bundle.zip\nZip file size: 200 bytes, number of entries: 1\nlrwxrwxrwx  2.0 unx        5 b-        5 stor 24-Jan-01 00:00 link -> ../etc/passwd\n',
          ''
        );
        return;
      }

      callback?.(null, '', '');
    });

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-zip-traversal',
        artifact: {
          type: 'archive',
          ref: { url: 'https://example.com/bundle.zip' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/unsafe symlink/);

    expect(execFileMock.mock.calls.some((call) => call[1].includes('-d'))).toBe(false);
  });

  it('rejects oci fetches when ALLOW_NETWORK_FETCH is disabled', async () => {
    process.env.ALLOW_NETWORK_FETCH = 'false';
    const fetcher = await loadFetcher();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({ jsonBody: { layers: [] } })));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-oci-disabled',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'https://registry.example.com',
            repository: 'demo/app',
            digest: 'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('rejects archive downloads targeting loopback hosts', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-loopback',
        artifact: {
          type: 'archive',
          ref: { url: 'https://127.0.0.1/bundle.tgz' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/private address/);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(lookupMockImpl).not.toHaveBeenCalled();
  });

  it('rejects archive downloads targeting private IPv4 hosts', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-private',
        artifact: {
          type: 'archive',
          ref: { url: 'https://10.0.0.5/bundle.zip' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/private address/);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(lookupMockImpl).not.toHaveBeenCalled();
  });

  it('rejects archive downloads targeting IPv4-mapped IPv6 private hosts', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-ipv4-mapped-private',
        artifact: {
          type: 'archive',
          ref: { url: 'https://[::ffff:10.0.0.5]/bundle.zip' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/private address/);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(lookupMockImpl).not.toHaveBeenCalled();
  });

  it('rejects archive downloads when DNS resolves to private addresses', async () => {
    const fetcher = await loadFetcherWithNetwork();

    lookupMockImpl.mockResolvedValueOnce([{ address: '10.0.0.5', family: 4 }]);

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-dns',
        artifact: {
          type: 'archive',
          ref: { url: 'https://files.example.com/bundle.tgz' }
        }
      })
    ).rejects.toThrow(/private address/);

    expect(lookupMockImpl).toHaveBeenCalledWith('files.example.com', expect.objectContaining({ all: true }));
  });

  it('rejects archive downloads when DNS resolves to IPv4-mapped IPv6 private addresses', async () => {
    const fetcher = await loadFetcherWithNetwork();

    lookupMockImpl.mockResolvedValueOnce([{ address: '::ffff:10.0.0.5', family: 6 }]);

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-dns-ipv4-mapped',
        artifact: {
          type: 'archive',
          ref: { url: 'https://files.example.com/bundle.tgz' }
        }
      })
    ).rejects.toThrow(/private address/);

    expect(lookupMockImpl).toHaveBeenCalledWith('files.example.com', expect.objectContaining({ all: true }));
  });

  it('attaches a dispatcher that blocks private DNS responses for archive downloads', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-dispatcher',
      artifact: {
        type: 'archive',
        ref: { url: 'https://files.example.com/bundle.zip' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit & {
      dispatcher?: AgentInstance;
    };

    expect(init?.dispatcher).toBeDefined();
    const lookupFn = init?.dispatcher?.options.connect?.lookup;
    expect(typeof lookupFn).toBe('function');

    lookupMockImpl.mockResolvedValue([{ address: '10.0.0.5', family: 4 }]);

    await expect(
      new Promise<void>((resolve, reject) => {
        lookupFn?.('files.example.com', {}, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      })
    ).rejects.toThrow(/private address/);
  });

  it('allows archive downloads targeting IPv4-mapped IPv6 public hosts', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-ipv4-mapped-public',
      artifact: {
        type: 'archive',
        ref: { url: 'https://[::ffff:203.0.113.50]/bundle.zip' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('closes the archive dispatcher after a successful download', async () => {
    const fetcher = await loadFetcherWithNetwork();

    let dispatcherInstance: AgentInstance | undefined;
    agentMock.mockImplementationOnce((options) => {
      dispatcherInstance = {
        options,
        dispatch: vi.fn(),
        close: vi.fn(() => Promise.resolve()),
        destroy: vi.fn(() => Promise.resolve())
      };
      return dispatcherInstance;
    });

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({})));

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-dispatcher-close',
      artifact: {
        type: 'archive',
        ref: { url: 'https://files.example.com/archive.zip' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    expect(dispatcherInstance).toBeDefined();
    expect(dispatcherInstance?.close).toHaveBeenCalledTimes(1);
    expect(dispatcherInstance?.destroy).not.toHaveBeenCalled();
  });

  it('destroys the archive dispatcher when download fails', async () => {
    const fetcher = await loadFetcherWithNetwork();

    let dispatcherInstance: AgentInstance | undefined;
    agentMock.mockImplementationOnce((options) => {
      dispatcherInstance = {
        options,
        dispatch: vi.fn(),
        close: vi.fn(() => Promise.resolve()),
        destroy: vi.fn(() => Promise.resolve())
      };
      return dispatcherInstance;
    });

    const fetchSpy = vi.fn(() => Promise.reject(new Error('archive fetch failed')));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive-dispatcher-destroy',
        artifact: {
          type: 'archive',
          ref: { url: 'https://files.example.com/archive.zip' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow('archive fetch failed');

    expect(dispatcherInstance).toBeDefined();
    expect(dispatcherInstance?.close).not.toHaveBeenCalled();
    expect(dispatcherInstance?.destroy).toHaveBeenCalledTimes(1);
  });

  it('rejects OCI registries that are not HTTPS', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve(createMockResponse({ jsonBody: { layers: [] } })));

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-oci-http',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'http://registry.example.com',
            repository: 'demo/app',
            tag: 'latest'
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/HTTPS/);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('disables redirects when fetching OCI manifests and layers', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const digest = 'sha256:9481e03b30dc453e917cb9520d0955ad05094aa4415df5c497a92fe994b474d5';
    const fetchSpy = vi.fn((url: string) => {
      if (url.includes('/manifests/')) {
        return Promise.resolve(
          createMockResponse({
            status: 200,
            jsonBody: { layers: [{ digest }] }
          })
        );
      }

      return Promise.resolve(
        createMockResponse({ status: 200, bodyChunks: [new TextEncoder().encode('layer-data')] })
      );
    });

    await fetcher.fetchArtifact({
      scanId: 'scan-oci-redirect',
      artifact: {
        type: 'oci',
        ref: {
          registry: 'https://registry.example.com',
          repository: 'demo/app',
          tag: 'latest'
        }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    const manifestCall = fetchSpy.mock.calls.find((call) => call[0].includes('/manifests/'));
    const layerCall = fetchSpy.mock.calls.find((call) => call[0].includes('/blobs/'));
    expect((manifestCall?.[1] as { redirect?: string } | undefined)?.redirect).toBe('manual');
    expect((layerCall?.[1] as { redirect?: string } | undefined)?.redirect).toBe('manual');
  });

  it('aborts OCI manifest requests that do not respond in time', async () => {
    const fetcher = await loadFetcherWithNetwork();
    vi.useFakeTimers();

    const fetchSpy = vi.fn((url: string, options?: RequestInit) => {
      if (url.includes('/manifests/')) {
        const signal = options?.signal as AbortSignal | undefined;
        return new Promise<Response>((_resolve, reject) => {
          const abortError = new Error('Aborted');
          abortError.name = 'AbortError';
          if (signal?.aborted) {
            reject(abortError);
            return;
          }

          const onAbort = () => {
            signal?.removeEventListener('abort', onAbort);
            reject(abortError);
          };

          signal?.addEventListener('abort', onAbort);
        });
      }

      return Promise.resolve(
        createMockResponse({
          jsonBody: { layers: [] }
        })
      );
    });

    try {
      const promise = fetcher.fetchArtifact({
        scanId: 'scan-oci-timeout-manifest',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'https://registry.example.com',
            repository: 'demo/app',
            tag: 'latest'
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      });

      const rejection = expect(promise).rejects.toThrow(/timed out/);

      await vi.advanceTimersByTimeAsync(30_001);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects OCI layers when the manifest declares a size above the limit', async () => {
    const fetcher = await loadFetcherWithNetwork();
    const digest = 'sha256:1111';
    const fetchSpy = vi.fn((url: string) => {
      if (url.includes('/manifests/')) {
        return Promise.resolve(
          createMockResponse({
            jsonBody: {
              layers: [
                {
                  digest,
                  size: 209_715_200 + 1
                }
              ]
            }
          })
        );
      }

      throw new Error(`Unexpected fetch for ${url}`);
    });

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-oci-manifest-oversize',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'https://registry.example.com',
            repository: 'demo/app',
            digest
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/declared size/);

    expect(fetchSpy.mock.calls.some((call) => call[0].includes('/blobs/'))).toBe(false);
  });

  it('rejects OCI layers when Content-Length exceeds the manifest size', async () => {
    const fetcher = await loadFetcherWithNetwork();
    const digest = 'sha256:2222';
    const fetchSpy = vi.fn((url: string) => {
      if (url.includes('/manifests/')) {
        return Promise.resolve(
          createMockResponse({ jsonBody: { layers: [{ digest, size: 100 }] } })
        );
      }

      return Promise.resolve(
        createMockResponse({
          headers: { 'content-length': '200' },
          bodyChunks: [new Uint8Array(50)]
        })
      );
    });

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-oci-content-length',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'https://registry.example.com',
            repository: 'demo/app',
            digest
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/Content-Length/);
  });

  it('streams OCI layer downloads into file handles', async () => {
    const fetcher = await loadFetcherWithNetwork();
    const encoder = new TextEncoder();
    const chunks = [encoder.encode('layer-a'), encoder.encode('layer-b')];
    const digestHash = createHash('sha256');
    for (const chunk of chunks) {
      digestHash.update(chunk);
    }
    const digest = `sha256:${digestHash.digest('hex')}`;
    const fetchSpy = vi.fn((url: string) => {
      if (url.includes('/manifests/')) {
        return Promise.resolve(
          createMockResponse({ jsonBody: { layers: [{ digest, size: 32 }] } })
        );
      }

      return Promise.resolve(
        createMockResponse({
          bodyChunks: chunks
        })
      );
    });

    await fetcher.fetchArtifact({
      scanId: 'scan-oci-stream',
      artifact: {
        type: 'oci',
        ref: {
          registry: 'https://registry.example.com',
          repository: 'demo/app',
          digest
        }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    expect(openHandles.length).toBeGreaterThan(0);
    const writes = openHandles.at(-1)?.writes ?? [];
    expect(writes).toHaveLength(2);
    const decoder = new TextDecoder();
    expect(decoder.decode(writes[0])).toBe('layer-a');
    expect(decoder.decode(writes[1])).toBe('layer-b');
  });

  it('aborts OCI layer streams when data transfer stalls', async () => {
    const fetcher = await loadFetcherWithNetwork();
    vi.useFakeTimers();

    const digest = 'sha256:slowlayerdigest';

    const fetchSpy = vi.fn((url: string, options?: RequestInit) => {
      if (url.includes('/manifests/')) {
        return Promise.resolve(
          createMockResponse({
            jsonBody: { layers: [{ digest }] }
          })
        );
      }

      if (url.includes('/blobs/')) {
        const signal = options?.signal as AbortSignal | undefined;
        const listeners: Array<() => void> = [];

        const bodyStream = {
          getReader() {
            return {
              read(): Promise<{ value?: Uint8Array; done: boolean }> {
                return new Promise((_resolve, reject) => {
                  const abortError = new Error('Aborted');
                  abortError.name = 'AbortError';

                  const onAbort = () => {
                    signal?.removeEventListener('abort', onAbort);
                    reject(abortError);
                  };

                  if (signal?.aborted) {
                    onAbort();
                    return;
                  }

                  listeners.push(onAbort);
                  signal?.addEventListener('abort', onAbort);
                });
              },
              async cancel() {
                listeners.splice(0).forEach((listener) => {
                  signal?.removeEventListener('abort', listener);
                });
              }
            };
          }
        };

        return Promise.resolve(
          createMockResponse({
            bodyChunks: null,
            bodyStream,
            headers: {}
          })
        );
      }

      throw new Error(`Unexpected fetch call for ${url}`);
    });

    try {
      const promise = fetcher.fetchArtifact({
        scanId: 'scan-oci-timeout-layer',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'https://registry.example.com',
            repository: 'demo/app',
            digest
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      });

      const rejection = expect(promise).rejects.toThrow(/timed out/);

      await vi.advanceTimersByTimeAsync(30_001);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses overridden binaries when provided', async () => {
    process.env.GIT_BIN = '/usr/local/bin/custom-git';
    process.env.TAR_BIN = '/opt/tools/custom-tar';
    process.env.UNZIP_BIN = '/opt/tools/custom-unzip';
    const fetcher = await loadFetcherWithNetwork();

    await fetcher.fetchArtifact({
      scanId: 'scan-git-custom',
      artifact: {
        type: 'git',
        ref: { url: 'https://example.com/repo.git' }
      }
    });

    const gitCall = execFileMock.mock.calls[0];
    expect(gitCall?.[0]).toBe('/usr/local/bin/custom-git');

    execFileMock.mockClear();

    const fetchSpy = vi.fn(() =>
      Promise.resolve(
        createMockResponse({ bodyChunks: [new TextEncoder().encode('archive')] })
      )
    );

    fsMock.rm.mockClear();
    fsMock.mkdir.mockClear();
    fsMock.writeFile.mockClear();

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-custom',
      artifact: {
        type: 'archive',
        ref: { url: 'https://example.com/bundle.tgz' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    const tarCall = execFileMock.mock.calls.find((call) => call[0] === '/opt/tools/custom-tar');
    expect(tarCall).toBeDefined();

    execFileMock.mockClear();

    await fetcher.fetchArtifact({
      scanId: 'scan-archive-zip-custom',
      artifact: {
        type: 'archive',
        ref: { url: 'https://example.com/bundle.zip' }
      },
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    const unzipCall = execFileMock.mock.calls.find((call) => call[0] === '/opt/tools/custom-unzip');
    expect(unzipCall).toBeDefined();
  });

  it('aborts archive downloads that exceed the timeout', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() =>
      Promise.reject(new DOMException('Aborted', 'AbortError'))
    );

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-archive',
        artifact: {
          type: 'archive',
          ref: { url: 'https://example.com/bundle.tgz' }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/timed out/);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('detects checksum mismatches for OCI layers', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn((url: string) => {
      if (url.includes('/manifests/')) {
        return Promise.resolve(
          createMockResponse({
            jsonBody: {
              layers: [
                {
                  digest: 'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
                }
              ]
            }
          })
        );
      }

      if (url.includes('/blobs/')) {
        return Promise.resolve(
          createMockResponse({ bodyChunks: [new TextEncoder().encode('layer-data')] })
        );
      }

      return Promise.resolve(createMockResponse({ status: 404, ok: false }));
    });

    await expect(
      fetcher.fetchArtifact({
        scanId: 'scan-oci',
        artifact: {
          type: 'oci',
          ref: {
            registry: 'https://registry.example.com',
            repository: 'demo/app',
            digest: 'sha256:abcdef'
          }
        },
        fetchImpl: fetchSpy as unknown as typeof fetch
      })
    ).rejects.toThrow(/Layer checksum mismatch/);
  });

  it('short-circuits archive downloads after repeated failures and recovers after cooldown', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));

    const fetcher = await loadFetcherWithNetwork();

    const fetchSpy = vi.fn(() => Promise.resolve({ ok: false, status: 500 } as unknown as Response));
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response);
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response);
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 500 } as unknown as Response);
    fetchSpy.mockResolvedValue(
      createMockResponse({ status: 200 })
    );

    const artifact = {
      type: 'archive' as const,
      ref: { url: 'https://downloads.example.com/app.zip' }
    };

    await expect(
      fetcher.fetchArtifact({ scanId: 'archive-1', artifact, fetchImpl: fetchSpy as unknown as typeof fetch })
    ).rejects.toThrow(/status 500/);

    vi.setSystemTime(new Date('2024-01-01T00:00:10Z'));
    await expect(
      fetcher.fetchArtifact({ scanId: 'archive-2', artifact, fetchImpl: fetchSpy as unknown as typeof fetch })
    ).rejects.toThrow(/status 500/);

    vi.setSystemTime(new Date('2024-01-01T00:00:20Z'));
    await expect(
      fetcher.fetchArtifact({ scanId: 'archive-3', artifact, fetchImpl: fetchSpy as unknown as typeof fetch })
    ).rejects.toThrow(/status 500/);

    expect(fetchSpy).toHaveBeenCalledTimes(3);

    vi.setSystemTime(new Date('2024-01-01T00:00:30Z'));
    await expect(
      fetcher.fetchArtifact({ scanId: 'archive-4', artifact, fetchImpl: fetchSpy as unknown as typeof fetch })
    ).rejects.toThrow(/temporarily disabled/);
    expect(fetchSpy).toHaveBeenCalledTimes(3);

    vi.setSystemTime(new Date('2024-01-01T00:02:00Z'));
    const result = await fetcher.fetchArtifact({
      scanId: 'archive-5',
      artifact,
      fetchImpl: fetchSpy as unknown as typeof fetch
    });

    expect(fetchSpy).toHaveBeenCalledTimes(4);
    expect(result.workspacePath).toContain('archive-5');

    vi.setSystemTime(new Date('2024-01-01T00:02:10Z'));
    const followUp = await fetcher.fetchArtifact({
      scanId: 'archive-6',
      artifact,
      fetchImpl: fetchSpy as unknown as typeof fetch
    });
    expect(followUp.artifactPath).toContain('archive-6');
  });

  it('short-circuits git fetches after repeated failures and allows half-open recovery', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));

    let cloneFailures = 0;
    const cloneError = Object.assign(new Error('network failure'), { stderr: 'fatal: network' });

    execFileMock.mockImplementation((command, args, _options, callback) => {
      if (args.includes('clone')) {
        if (cloneFailures < 3) {
          cloneFailures += 1;
          callback?.(cloneError as Error, '', 'fatal: network');
          return;
        }
      }

      callback?.(null, '', '');
    });

    const fetcher = await loadFetcherWithNetwork();

    const artifact = {
      type: 'git' as const,
      ref: { url: 'https://example.com/repo.git' }
    };

    await expect(fetcher.fetchArtifact({ scanId: 'git-1', artifact })).rejects.toThrow(/network failure/);

    vi.setSystemTime(new Date('2024-01-01T00:00:10Z'));
    await expect(fetcher.fetchArtifact({ scanId: 'git-2', artifact })).rejects.toThrow(/network failure/);

    vi.setSystemTime(new Date('2024-01-01T00:00:20Z'));
    await expect(fetcher.fetchArtifact({ scanId: 'git-3', artifact })).rejects.toThrow(/network failure/);

    expect(cloneFailures).toBe(3);
    expect(execFileMock).toHaveBeenCalledTimes(3);

    vi.setSystemTime(new Date('2024-01-01T00:00:30Z'));
    await expect(fetcher.fetchArtifact({ scanId: 'git-4', artifact })).rejects.toThrow(/temporarily disabled/);
    expect(cloneFailures).toBe(3);
    expect(execFileMock).toHaveBeenCalledTimes(3);

    vi.setSystemTime(new Date('2024-01-01T00:02:00Z'));
    const result = await fetcher.fetchArtifact({ scanId: 'git-5', artifact });

    expect(result.artifactPath).toContain('git-5');
    expect(cloneFailures).toBe(3);
    expect(execFileMock).toHaveBeenCalledTimes(4);

    vi.setSystemTime(new Date('2024-01-01T00:02:10Z'));
    await expect(fetcher.fetchArtifact({ scanId: 'git-6', artifact })).resolves.toBeDefined();
    expect(cloneFailures).toBe(3);
    expect(execFileMock).toHaveBeenCalledTimes(5);
  });

  it('cleans up workspaces when requested', async () => {
    const fetcher = await loadFetcherWithNetwork();

    const workspacePath = fetcher.resolveWorkspacePath('scan-cleanup');
    await fetcher.cleanupWorkspace(workspacePath);

    expect(fsMock.rm).toHaveBeenLastCalledWith(workspacePath, { recursive: true, force: true });
  });
});
