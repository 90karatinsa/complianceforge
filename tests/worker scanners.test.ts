// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { posix as path } from 'node:path';
import type { OsvVulnerability } from '../worker/src/scanners.ts';

type EntryType = 'file' | 'dir';

class MockDirent {
  constructor(public readonly name: string, private readonly type: EntryType) {}

  isDirectory(): boolean {
    return this.type === 'dir';
  }

  isFile(): boolean {
    return this.type === 'file';
  }
}

const files = new Map<string, string>();
const directories = new Set<string>();

function normalize(target: string): string {
  const normalized = path.normalize(target).replace(/\\/gu, '/');
  if (normalized.length > 1 && normalized.endsWith('/')) {
    return normalized.slice(0, -1);
  }

  return normalized;
}

function ensureDir(dirPath: string): void {
  let current = normalize(dirPath);

  if (directories.has(current)) {
    return;
  }

  directories.add(current);

  if (current !== '/') {
    const parent = path.dirname(current);
    if (parent && parent !== current) {
      ensureDir(parent);
    }
  }
}

function addFile(filePath: string, contents: string): void {
  const normalized = normalize(filePath);
  ensureDir(path.dirname(normalized));
  files.set(normalized, contents);
}

function listChildren(dirPath: string): Map<string, EntryType> {
  const normalized = normalize(dirPath);
  const entries = new Map<string, EntryType>();

  for (const directory of directories) {
    if (directory === normalized) {
      continue;
    }

    if (path.dirname(directory) === normalized) {
      entries.set(path.basename(directory), 'dir');
    }
  }

  for (const file of files.keys()) {
    if (path.dirname(file) === normalized) {
      entries.set(path.basename(file), 'file');
    }
  }

  return entries;
}

const fsMock = {
  readFile: vi.fn((filePath: string, encoding: string | undefined = 'utf8') => {
    const normalized = normalize(filePath);
    const value = files.get(normalized);

    if (value === undefined) {
      const error = new Error(`ENOENT: no such file or directory, open '${normalized}'`) as Error & {
        code?: string;
      };
      error.code = 'ENOENT';
      return Promise.reject(error);
    }

    if (encoding === 'utf8') {
      return Promise.resolve(value);
    }

    return Promise.resolve(Buffer.from(value, 'utf8'));
  }),
  readdir: vi.fn((dirPath: string, options?: { withFileTypes?: boolean }) => {
    const entries = listChildren(dirPath);
    const names = Array.from(entries.entries()).sort(([a], [b]) => a.localeCompare(b));

    if (options?.withFileTypes) {
      return Promise.resolve(names.map(([name, type]) => new MockDirent(name, type)));
    }

    return Promise.resolve(names.map(([name]) => name));
  }),
  stat: vi.fn((targetPath: string) => {
    const normalized = normalize(targetPath);

    if (directories.has(normalized)) {
      return Promise.resolve({
        isDirectory: () => true,
        isFile: () => false
      } as const);
    }

    if (files.has(normalized)) {
      return Promise.resolve({
        isDirectory: () => false,
        isFile: () => true
      } as const);
    }

    const error = new Error(`ENOENT: no such file or directory, stat '${normalized}'`) as Error & {
      code?: string;
    };
    error.code = 'ENOENT';
    return Promise.reject(error);
  })
};

vi.mock('node:fs/promises', () => fsMock);

function loadScanners(): Promise<typeof import('../worker/src/scanners.ts')> {
  return import('../worker/src/scanners.ts');
}

function loadScannersWithNetwork(): Promise<typeof import('../worker/src/scanners.ts')> {
  process.env.ALLOW_NETWORK_FETCH = 'true';
  return loadScanners();
}

describe('worker scanners', () => {
  const workspaceRoot = '/workspace';
  const layersRoot = '/workspace/oci';
  const originalAllowNetworkFetch = process.env.ALLOW_NETWORK_FETCH;

  beforeEach(() => {
    files.clear();
    directories.clear();
    ensureDir('/');
    ensureDir(workspaceRoot);
    ensureDir(layersRoot);
    fsMock.readFile.mockClear();
    fsMock.readdir.mockClear();
    fsMock.stat.mockClear();
    vi.resetModules();
    if (originalAllowNetworkFetch === undefined) {
      delete process.env.ALLOW_NETWORK_FETCH;
    } else {
      process.env.ALLOW_NETWORK_FETCH = originalAllowNetworkFetch;
    }
  });

  afterEach(() => {
    if (originalAllowNetworkFetch === undefined) {
      delete process.env.ALLOW_NETWORK_FETCH;
    } else {
      process.env.ALLOW_NETWORK_FETCH = originalAllowNetworkFetch;
    }
    vi.useRealTimers();
  });

  function seedWorkspace(): void {
    addFile(
      path.join(workspaceRoot, 'package-lock.json'),
      JSON.stringify({
        packages: {
          '': { name: 'demo', version: '1.0.0' },
          'node_modules/lodash': { version: '4.17.21' }
        }
      })
    );
    ensureDir(path.join(workspaceRoot, 'node_modules/lodash'));
    addFile(path.join(workspaceRoot, 'node_modules/lodash/LICENSE'), 'MIT License');

    addFile(
      path.join(workspaceRoot, 'requirements.txt'),
      ['requests==2.31.0', '# comment', ''].join('\n')
    );
    ensureDir(path.join(workspaceRoot, 'vendor/site-packages/requests'));
    addFile(
      path.join(workspaceRoot, 'vendor/site-packages/requests/LICENSE'),
      'Apache License Version 2.0'
    );

    addFile(
      path.join(workspaceRoot, 'poetry.lock'),
      [
        '[[package]]',
        'name = "urllib3"',
        'version = "2.0.7"',
        '',
        '[[package]]',
        'name = "idna"',
        'version = "3.4"'
      ].join('\n')
    );

    addFile(
      path.join(workspaceRoot, 'go.mod'),
      ['module example.com/app', '', 'require (', '  github.com/pkg/errors v0.9.1', ')'].join('\n')
    );
    addFile(
      path.join(workspaceRoot, 'go.sum'),
      ['github.com/pkg/errors v0.9.1 h1:abcdef', 'github.com/pkg/errors v0.9.1/go.mod h1:def'].join('\n')
    );
    ensureDir(path.join(workspaceRoot, 'github.com/pkg/errors'));
    addFile(path.join(workspaceRoot, 'github.com/pkg/errors/LICENSE'), 'BSD 3-Clause License');

    addFile(
      path.join(layersRoot, 'packages.json'),
      JSON.stringify({
        packages: [
          { name: 'ghcr.io/demo/app', version: '1.2.3' },
          { name: 'ghcr.io/demo/app', version: '1.2.3' }
        ]
      })
    );

    addFile(
      path.join(workspaceRoot, 'Gemfile.lock'),
      [
        'GEM',
        '  specs:',
        '    rack (3.0.8)',
        '',
        'PLATFORMS',
        '  ruby'
      ].join('\n')
    );
    ensureDir(path.join(workspaceRoot, 'vendor/bundle/ruby/3.1.0/gems/rack-3.0.8'));
    addFile(
      path.join(workspaceRoot, 'vendor/bundle/ruby/3.1.0/gems/rack-3.0.8/LICENSE'),
      'MIT License'
    );

    addFile(
      path.join(workspaceRoot, 'Cargo.lock'),
      [
        '[[package]]',
        'name = "serde"',
        'version = "1.0.188"',
        '',
        '[[package]]',
        'name = "tokio"',
        'version = "1.34.0"'
      ].join('\n')
    );
    ensureDir(path.join(workspaceRoot, 'registry/src/github.com-1ecc6299db9ec823/serde-1.0.188'));
    addFile(
      path.join(
        workspaceRoot,
        'registry/src/github.com-1ecc6299db9ec823/serde-1.0.188/LICENSE'
      ),
      'Apache License Version 2.0'
    );

    addFile(
      path.join(workspaceRoot, 'pom.xml'),
      [
        '<project>',
        '  <modelVersion>4.0.0</modelVersion>',
        '  <groupId>com.example</groupId>',
        '  <artifactId>demo-app</artifactId>',
        '  <version>1.0.0</version>',
        '  <dependencies>',
        '    <dependency>',
        '      <groupId>com.example</groupId>',
        '      <artifactId>demo-core</artifactId>',
        '      <version>1.2.3</version>',
        '    </dependency>',
        '    <dependency>',
        '      <groupId>org.sample</groupId>',
        '      <artifactId>util-lib</artifactId>',
        '      <version>4.5.6</version>',
        '    </dependency>',
        '    <dependency>',
        '      <groupId>org.test</groupId>',
        '      <artifactId>ignored-test</artifactId>',
        '      <version>9.9.9</version>',
        '      <scope>test</scope>',
        '    </dependency>',
        '  </dependencies>',
        '</project>'
      ].join('\n')
    );

    addFile(
      path.join(workspaceRoot, 'gradle.lockfile'),
      [
        '# Generated by Gradle',
        // Gradle 8+ lockfiles encode the version before the equals sign.
        // Supported patterns:
        //   group:artifact:version=configuration
        //   group:artifact:packaging:version=configuration
        //   group:artifact:packaging:classifier:version=configuration
        'com.example:demo:1.2.3=compileClasspath',
        // Legacy format where the version lives after the equals sign.
        'com.acme:gradle-util=7.8.9'
      ].join('\n')
    );

    ensureDir(path.join(workspaceRoot, 'modules/library'));
    addFile(
      path.join(workspaceRoot, 'modules/library/pom.xml'),
      [
        '<project>',
        '  <modelVersion>4.0.0</modelVersion>',
        '  <groupId>modules.library</groupId>',
        '  <artifactId>library-parent</artifactId>',
        '  <version>1.0.0</version>',
        '  <dependencies>',
        '    <dependency>',
        '      <groupId>org.extra</groupId>',
        '      <artifactId>nested-lib</artifactId>',
        '      <version>0.9.0</version>',
        '    </dependency>',
        '  </dependencies>',
        '</project>'
      ].join('\n')
    );

    ensureDir(path.join(workspaceRoot, 'services/api'));
    addFile(
      path.join(workspaceRoot, 'services/api/gradle.lockfile'),
      [
        '# Service lockfile',
        'org.other:service-core=3.2.1',
        'org.other:service-core:jar:javadoc:3.2.1=runtimeClasspath'
      ].join('\n')
    );

    addFile(
      path.join(workspaceRoot, 'packages.lock.json'),
      JSON.stringify(
        {
          version: 1,
          dependencies: {
            'net8.0': {
              'Newtonsoft.Json': {
                type: 'Direct',
                resolved: '13.0.1'
              }
            }
          }
        },
        null,
        2
      )
    );

    ensureDir(path.join(workspaceRoot, 'src/Services'));
    addFile(
      path.join(workspaceRoot, 'src/Services/packages.lock.json'),
      JSON.stringify(
        {
          version: 1,
          dependencies: {
            'net7.0': {
              Dapper: {
                type: 'Transitive',
                resolved: '2.1.0'
              },
              Placeholder: {
                version: '$(PlaceholderVersion)'
              }
            }
          }
        },
        null,
        2
      )
    );

    addFile(
      path.join(workspaceRoot, 'Demo.csproj'),
      [
        '<Project Sdk="Microsoft.NET.Sdk">',
        '  <PropertyGroup>',
        '    <TargetFramework>net8.0</TargetFramework>',
        '  </PropertyGroup>',
        '  <ItemGroup>',
        '    <PackageReference Include="Serilog" Version="2.12.0" />',
        '    <PackageReference Include="Polly">',
        '      <Version>7.2.3</Version>',
        '    </PackageReference>',
        '    <PackageReference Include="Versionless" />',
        '  </ItemGroup>',
        '</Project>'
      ].join('\n')
    );

    addFile(
      path.join(workspaceRoot, 'src/Services/Service.csproj'),
      [
        '<Project Sdk="Microsoft.NET.Sdk.Web">',
        '  <PropertyGroup>',
        '    <TargetFramework>net7.0</TargetFramework>',
        '  </PropertyGroup>',
        '  <ItemGroup>',
        '    <PackageReference Include="Flurl.Http" Version="3.2.0" />',
        '    <PackageReference Include="SkipVersion">',
        '      <Version>$(Version)</Version>',
        '    </PackageReference>',
        '  </ItemGroup>',
        '</Project>'
      ].join('\n')
    );

    addFile(path.join(layersRoot, 'apk-installed'), ['openssl 3.1.2-r0', 'busybox 1.36.1-r2'].join('\n'));

    ensureDir(path.join(layersRoot, 'var/lib/dpkg'));
    addFile(
      path.join(layersRoot, 'var/lib/dpkg/status'),
      [
        'Package: ca-certificates',
        'Version: 20230311',
        '',
        'Package: libc6',
        'Version: 2.37-0'
      ].join('\n')
    );

    addFile(
      path.join(layersRoot, 'rpm-packages.json'),
      JSON.stringify({ packages: [{ name: 'bash', version: '5.2.15' }] })
    );
  }

  it('builds a CycloneDX BOM with license mappings and vulnerabilities', async () => {
    seedWorkspace();

    const fetchSpy = vi.fn((_url: string, init?: RequestInit) => {
      const body = JSON.parse((init?.body as string) ?? '{}') as {
        queries?: Array<{ package: { name: string; ecosystem: string }; version: string }>;
      };
      const results = body.queries?.map((query) => {
        if (query.package.name === 'lodash') {
          return { vulns: [{ id: 'GHSA-xxxx', summary: 'Prototype pollution' }] };
        }

        return { vulns: [] };
      }) ?? [];

      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ results })
      } as Response);
    });

    const scanners = await loadScannersWithNetwork();
    const now = new Date('2024-01-01T00:00:00.000Z');

    const result = await scanners.runScanners(workspaceRoot, {
      ociLayersPath: layersRoot,
      fetchImpl: fetchSpy as unknown as typeof fetch,
      cache: new Map(),
      now: () => now
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const queryBody = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string) as {
      queries?: unknown[];
    };
    expect(Array.isArray(queryBody.queries)).toBe(true);
    expect(queryBody.queries).toHaveLength(result.packages.length);

    const purls = result.packages.map((pkg) => pkg.purl).sort();
    expect(purls).toEqual([
      'pkg:apk/alpine/busybox@1.36.1-r2',
      'pkg:apk/alpine/openssl@3.1.2-r0',
      'pkg:cargo/serde@1.0.188',
      'pkg:cargo/tokio@1.34.0',
      'pkg:deb/debian/ca-certificates@20230311',
      'pkg:deb/debian/libc6@2.37-0',
      'pkg:gem/rack@3.0.8',
      'pkg:golang/github.com/pkg/errors@v0.9.1',
      'pkg:maven/com/acme/gradle-util@7.8.9',
      'pkg:maven/com/example/demo-core@1.2.3',
      'pkg:maven/com/example/demo@1.2.3',
      'pkg:maven/org/extra/nested-lib@0.9.0',
      'pkg:maven/org/other/service-core@3.2.1',
      'pkg:maven/org/other/service-core@3.2.1?type=jar&classifier=javadoc',
      'pkg:maven/org/sample/util-lib@4.5.6',
      'pkg:npm/lodash@4.17.21',
      'pkg:nuget/Dapper@2.1.0',
      'pkg:nuget/Flurl.Http@3.2.0',
      'pkg:nuget/Newtonsoft.Json@13.0.1',
      'pkg:nuget/Polly@7.2.3',
      'pkg:nuget/Serilog@2.12.0',
      'pkg:oci/ghcr.io/demo/app@1.2.3',
      'pkg:pypi/idna@3.4',
      'pkg:pypi/requests@2.31.0',
      'pkg:pypi/urllib3@2.0.7',
      'pkg:rpm/redhat/bash@5.2.15'
    ]);

    expect(result.packages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'com.example:demo-core',
          version: '1.2.3',
          ecosystem: 'maven'
        }),
        expect.objectContaining({
          name: 'org.extra:nested-lib',
          version: '0.9.0',
          ecosystem: 'maven'
        }),
        expect.objectContaining({
          name: 'Newtonsoft.Json',
          version: '13.0.1',
          ecosystem: 'nuget'
        }),
        expect.objectContaining({
          name: 'Flurl.Http',
          version: '3.2.0',
          ecosystem: 'nuget'
        })
      ])
    );

    expect(result.bom.metadata.timestamp).toBe(now.toISOString());
    const lodashComponent = result.bom.components.find((component) => component.name === 'lodash');
    expect(lodashComponent?.licenses).toEqual([{ license: { id: 'MIT' } }]);

    const requestsComponent = result.bom.components.find((component) => component.name === 'requests');
    expect(requestsComponent?.licenses).toEqual([{ license: { id: 'Apache-2.0' } }]);

    const errorsComponent = result.bom.components.find((component) => component.name === 'github.com/pkg/errors');
    expect(errorsComponent?.licenses).toEqual([{ license: { id: 'BSD-3-Clause' } }]);

    const rackComponent = result.bom.components.find((component) => component.name === 'rack');
    expect(rackComponent?.licenses).toEqual([{ license: { id: 'MIT' } }]);

    const serdeComponent = result.bom.components.find((component) => component.name === 'serde');
    expect(serdeComponent?.licenses).toEqual([{ license: { id: 'Apache-2.0' } }]);

    const lodashVulnerability = result.vulnerabilities.find((entry) => entry.package.name === 'lodash');
    expect(lodashVulnerability?.vulnerabilities[0]?.id).toBe('GHSA-xxxx');
  });

  it('parses Yarn v1 lockfiles for npm packages', async () => {
    addFile(
      path.join(workspaceRoot, 'yarn.lock'),
      [
        '"left-pad@^1.0.0":',
        '  version "1.0.0"',
        '  resolved "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"',
        '',
        '"@scope/pkg@~2.0.0":',
        '  version "2.1.0"',
        '  resolved "https://registry.npmjs.org/@scope/pkg/-/pkg-2.1.0.tgz"'
      ].join('\n')
    );

    const { collectNodePackages } = await loadScannersWithNetwork();
    const packages = await collectNodePackages(workspaceRoot);

    expect(Array.from(packages.values())).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'left-pad', version: '1.0.0', ecosystem: 'npm' }),
        expect.objectContaining({ name: '@scope/pkg', version: '2.1.0', ecosystem: 'npm' })
      ])
    );
  });

  it('parses Yarn Berry lockfiles for npm packages', async () => {
    addFile(
      path.join(workspaceRoot, 'yarn.lock'),
      [
        '__metadata:',
        '  version: 6',
        '  cacheKey: 1234',
        '',
        '"left-pad@npm:1.3.0":',
        '  version: 1.3.0',
        '  resolution: "left-pad@npm:1.3.0"',
        '',
        '"lodash@npm:4.17.21":',
        '  version: 4.17.21',
        '  resolution: "lodash@npm:4.17.21"',
        '',
        '"workspace-only@workspace:*":',
        '  version: 0.0.0'
      ].join('\n')
    );

    const { collectNodePackages } = await loadScannersWithNetwork();
    const packages = await collectNodePackages(workspaceRoot);

    expect(Array.from(packages.values())).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'left-pad', version: '1.3.0', ecosystem: 'npm' }),
        expect.objectContaining({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' })
      ])
    );
    expect(Array.from(packages.values())).toEqual(
      expect.not.arrayContaining([
        expect.objectContaining({ name: 'workspace-only', ecosystem: 'npm' })
      ])
    );
  });

  it('persists OSV cache entries and reuses them on subsequent runs', async () => {
    addFile(
      path.join(workspaceRoot, 'package-lock.json'),
      JSON.stringify({
        packages: {
          '': { name: 'demo', version: '1.0.0' },
          'node_modules/lodash': { version: '4.17.21' }
        }
      })
    );
    ensureDir(path.join(workspaceRoot, 'node_modules/lodash'));
    addFile(path.join(workspaceRoot, 'node_modules/lodash/LICENSE'), 'MIT License');

    const fetchMock = vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ results: [{ vulns: [{ id: 'OSV-2024-0001' }] }] })
      } as unknown as Response)
    );
    const persistCache = vi.fn(() => Promise.resolve());
    const cache = new Map<string, OsvVulnerability[]>();

    const { runScanners } = await loadScannersWithNetwork();

    await runScanners(workspaceRoot, {
      fetchImpl: fetchMock as unknown as typeof fetch,
      cache,
      persistCache
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(persistCache).toHaveBeenCalledWith(
      'pkg:npm/lodash@4.17.21',
      expect.arrayContaining([expect.objectContaining({ id: 'OSV-2024-0001' })])
    );

    fetchMock.mockClear();
    persistCache.mockClear();

    await runScanners(workspaceRoot, {
      fetchImpl: fetchMock as unknown as typeof fetch,
      cache,
      persistCache
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(persistCache).not.toHaveBeenCalled();
  });

  it('rejects OSV lookups when ALLOW_NETWORK_FETCH is disabled', async () => {
    seedWorkspace();
    process.env.ALLOW_NETWORK_FETCH = 'false';
    const fetchMock = vi.fn();
    const { runScanners } = await loadScanners();

    await expect(
      runScanners(workspaceRoot, {
        fetchImpl: fetchMock as unknown as typeof fetch,
        cache: new Map<string, OsvVulnerability[]>()
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects OSV lookups when ALLOW_NETWORK_FETCH is unset', async () => {
    seedWorkspace();
    const fetchMock = vi.fn();
    const { runScanners } = await loadScanners();

    await expect(
      runScanners(workspaceRoot, {
        fetchImpl: fetchMock as unknown as typeof fetch,
        cache: new Map<string, OsvVulnerability[]>()
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('associates license findings with scoped and nested node modules', async () => {
    addFile(
      path.join(workspaceRoot, 'package-lock.json'),
      JSON.stringify({
        packages: {
          '': { name: 'demo', version: '1.0.0' },
          'node_modules/@scope/pkg': { name: '@scope/pkg', version: '2.3.4' },
          'node_modules/foo': { name: 'foo', version: '1.2.3' },
          'node_modules/foo/node_modules/bar': { name: 'bar', version: '0.4.5' }
        }
      })
    );

    ensureDir(path.join(workspaceRoot, 'node_modules/@scope/pkg'));
    ensureDir(path.join(workspaceRoot, 'node_modules/foo/node_modules/bar'));

    addFile(
      path.join(workspaceRoot, 'node_modules/@scope/pkg/LiCeNsE.md'),
      'MIT License'
    );
    addFile(
      path.join(workspaceRoot, 'node_modules/foo/node_modules/bar/Copying.TXT'),
      'BSD 3-Clause License'
    );

    const fetchSpy = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ results: [] })
      } as Response)
    );

    const scanners = await loadScannersWithNetwork();
    const result = await scanners.runScanners(workspaceRoot, {
      fetchImpl: fetchSpy as unknown as typeof fetch,
      cache: new Map()
    });

    const scopedFinding = result.licenses.find((entry) =>
      entry.path.includes('node_modules/@scope/pkg')
    );
    expect(scopedFinding?.packageName).toBe('@scope/pkg');
    expect(scopedFinding?.spdxId).toBe('MIT');

    const nestedFinding = result.licenses.find((entry) =>
      entry.path.includes('node_modules/foo/node_modules/bar')
    );
    expect(nestedFinding?.packageName).toBe('bar');
    expect(nestedFinding?.spdxId).toBe('BSD-3-Clause');
  });

  it('detects additional license filename variants', async () => {
    ensureDir(path.join(workspaceRoot, 'node_modules/demo-pkg'));
    ensureDir(path.join(workspaceRoot, 'vendor/site-packages/demo_copying'));
    ensureDir(path.join(workspaceRoot, 'node_modules/copyrighted'));

    addFile(
      path.join(workspaceRoot, 'node_modules/demo-pkg/Licence'),
      'MIT License'
    );
    addFile(
      path.join(workspaceRoot, 'vendor/site-packages/demo_copying/COPYING.md'),
      'Apache License Version 2.0'
    );
    addFile(path.join(workspaceRoot, 'node_modules/copyrighted/Copyright'), 'BSD 3-Clause License');

    const fetchSpy = vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({ results: [] }) } as Response)
    );

    const scanners = await loadScannersWithNetwork();
    const result = await scanners.runScanners(workspaceRoot, {
      fetchImpl: fetchSpy as unknown as typeof fetch,
      cache: new Map()
    });

    expect(result.licenses).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: expect.stringContaining('Licence'), spdxId: 'MIT' }),
        expect.objectContaining({ path: expect.stringContaining('COPYING.md'), spdxId: 'Apache-2.0' }),
        expect.objectContaining({ path: expect.stringContaining('Copyright'), spdxId: 'BSD-3-Clause' })
      ])
    );
  });

  it('reuses cached vulnerability lookups', async () => {
    seedWorkspace();

    const fetchSpy = vi.fn((_url: string, init?: RequestInit) => {
      const body = JSON.parse((init?.body as string) ?? '{}') as {
        queries?: unknown[];
      };
      return Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve({
            results: (body.queries ?? []).map(() => ({ vulns: [] }))
          })
      } as Response);
    });

    const cache = new Map<string, OsvVulnerability[]>();
    const scanners = await loadScannersWithNetwork();

    await scanners.runScanners(workspaceRoot, {
      ociLayersPath: layersRoot,
      fetchImpl: fetchSpy as unknown as typeof fetch,
      cache
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);

    fetchSpy.mockClear();

    await scanners.runScanners(workspaceRoot, {
      ociLayersPath: layersRoot,
      fetchImpl: fetchSpy as unknown as typeof fetch,
      cache
    });

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('runs package collectors in parallel while preserving sorted output', async () => {
    const scanners = await loadScannersWithNetwork();
    const releaseMap = new Map<string, () => void>();
    const originalReadFile = fsMock.readFile.getMockImplementation();

    if (!originalReadFile) {
      throw new Error('original readFile implementation missing');
    }

    const packageLockPath = normalize(path.join(workspaceRoot, 'package-lock.json'));
    const requirementsPath = normalize(path.join(workspaceRoot, 'requirements.txt'));

    addFile(
      packageLockPath,
      JSON.stringify({
        packages: {
          '': { name: 'npm-demo', version: '1.0.0' },
          'node_modules/npm-demo': { version: '1.0.0' }
        }
      })
    );
    addFile(requirementsPath, 'requests==2.0.0');

    fsMock.readFile.mockImplementation((filePath: string, encoding?: string) => {
      const normalizedPath = normalize(filePath);

      if (normalizedPath === packageLockPath || normalizedPath === requirementsPath) {
        return new Promise((resolve) => {
          releaseMap.set(normalizedPath, () => {
            resolve(originalReadFile(filePath, encoding));
          });
        });
      }

      return originalReadFile(filePath, encoding);
    });

    const fetchSpy = vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({ results: [] }) } as Response)
    );

    try {
      const runPromise = scanners.runScanners(workspaceRoot, {
        fetchImpl: fetchSpy as unknown as typeof fetch,
        cache: new Map()
      });

      await Promise.resolve();
      await Promise.resolve();
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(releaseMap.has(packageLockPath)).toBe(true);
      expect(releaseMap.has(requirementsPath)).toBe(true);

      releaseMap.forEach((release) => release());

      const result = await runPromise;

      expect(result.packages.map((pkg) => pkg.purl)).toEqual([
        'pkg:npm/npm-demo@1.0.0',
        'pkg:pypi/requests@2.0.0'
      ]);
    } finally {
      fsMock.readFile.mockImplementation(originalReadFile);
    }
  });

  it('applies custom OSV retry configuration', async () => {
    seedWorkspace();

    const fetchSpy = vi.fn(() =>
      Promise.resolve({
        ok: false,
        status: 503,
        json: () => Promise.resolve({ results: [] })
      } as unknown as Response)
    );

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const scanners = await loadScannersWithNetwork();

    try {
      await scanners.runScanners(workspaceRoot, {
        ociLayersPath: layersRoot,
        fetchImpl: fetchSpy as unknown as typeof fetch,
        cache: new Map(),
        osvRetryOptions: { maxAttempts: 1, timeoutMs: 5, baseDelayMs: 1 }
      });
    } finally {
      warnSpy.mockRestore();
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('returns cached vulnerabilities when OSV batch calls fail', async () => {
    seedWorkspace();

    const cachedVuln: OsvVulnerability = { id: 'OSV-2024-9999' };
    const cache = new Map<string, OsvVulnerability[]>([
      ['pkg:npm/lodash@4.17.21', [cachedVuln]]
    ]);

    const fetchSpy = vi.fn(() => Promise.reject(new Error('network unreachable')));
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const scanners = await loadScannersWithNetwork();

    try {
      const result = await scanners.runScanners(workspaceRoot, {
        ociLayersPath: layersRoot,
        fetchImpl: fetchSpy as unknown as typeof fetch,
        cache,
        osvRetryOptions: { maxAttempts: 1 }
      });

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Failed to query OSV batch endpoint'));

      const lodashFinding = result.vulnerabilities.find((entry) => entry.package.name === 'lodash');
      expect(lodashFinding?.vulnerabilities).toEqual([cachedVuln]);

      const opensslFinding = result.vulnerabilities.find((entry) => entry.package.name === 'openssl');
      expect(opensslFinding?.vulnerabilities).toEqual([]);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
