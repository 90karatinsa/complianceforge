// SPDX-License-Identifier: MIT

import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type ExecFileOptions = { env?: Record<string, string | undefined>; stdio?: 'pipe' };
type ExecFileCallback = (error: Error | null, stdout: string, stderr: string) => void;

type ExecFileMockArgs = [string, readonly string[], ExecFileOptions | undefined, ExecFileCallback];

const execFileMock = vi.hoisted(() => vi.fn<(...args: ExecFileMockArgs) => void>());

vi.mock('node:child_process', () => ({
  execFile: (
    file: string,
    args: readonly string[],
    options: ExecFileOptions | ExecFileCallback | undefined,
    maybeCallback?: ExecFileCallback
  ) => {
    const execOptions = typeof options === 'function' ? undefined : options;
    const callback = typeof options === 'function' ? options : maybeCallback;
    if (!callback) {
      throw new Error('execFile callback not provided');
    }
    execFileMock(file, args, execOptions, callback);
  }
}));

import { generateSbom } from '../../scripts/generate-sbom.ts';

const BASE_ENV = { ...process.env };

function assertCall<TArgs extends unknown[]>(call: TArgs | undefined, message: string): asserts call is TArgs {
  if (!call) {
    throw new Error(message);
  }
}

beforeEach(() => {
  execFileMock.mockReset();
  execFileMock.mockImplementation((_, __, ___, callback) => {
    callback(null, '', '');
  });
  process.env = { ...BASE_ENV };
});

afterEach(() => {
  process.env = { ...BASE_ENV };
});

describe('generateSbom', () => {
  it('creates deterministic CycloneDX SBOM output', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sbom-'));
    await mkdir(root, { recursive: true });
    const pkg = { name: 'demo-app', version: '1.2.3' };
    const lock = {
      name: 'demo-app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo-app', version: '1.2.3' },
        'node_modules/alpha': { name: 'alpha', version: '1.0.0', license: 'MIT' },
        'node_modules/@scope/beta': { name: '@scope/beta', version: '0.5.0', license: 'Apache-2.0' }
      }
    };
    await writeFile(path.join(root, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`, 'utf8');
    await writeFile(path.join(root, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`, 'utf8');

    const { cycloneDx, spdx, componentCount, cycloneDxSignaturePath, spdxSignaturePath } = await generateSbom({
      packageJsonPath: path.join(root, 'package.json'),
      packageLockPath: path.join(root, 'package-lock.json'),
      timestamp: new Date('2024-01-01T00:00:00.000Z'),
      logger: () => {}
    });

    expect(componentCount).toBe(2);
    expect(cycloneDxSignaturePath).toBeUndefined();
    expect(spdxSignaturePath).toBeUndefined();
    expect(cycloneDx.bomFormat).toBe('CycloneDX');
    expect(cycloneDx.specVersion).toBe('1.5');
    expect((cycloneDx.metadata as Record<string, unknown>).timestamp).toBe('2024-01-01T00:00:00.000Z');
    const components = (cycloneDx.components as Array<Record<string, unknown>>) ?? [];
    expect(components.map((component) => component.purl)).toEqual([
      'pkg:npm/%40scope/beta@0.5.0',
      'pkg:npm/alpha@1.0.0'
    ]);
    expect(typeof cycloneDx.serialNumber).toBe('string');

    expect(spdx.spdxVersion).toBe('SPDX-2.3');
    const spdxPackages = (spdx.packages as Array<Record<string, unknown>>) ?? [];
    expect(spdxPackages).toHaveLength(2);
    const firstExternalRefs = (spdxPackages[0]?.externalRefs as Array<Record<string, unknown>> | undefined) ?? [];
    expect((firstExternalRefs[0]?.referenceLocator as string | undefined) ?? '').toMatch(/pkg:npm/);
    const relationships = (spdx.relationships as Array<Record<string, unknown>>) ?? [];
    expect(relationships.every((relation) => relation.relationshipType === 'DESCRIBES')).toBe(true);
  });

  it('signs the SBOM when COSIGN_KEY_REF is provided', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sbom-sign-'));
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, 'package.json'), '{ "name": "signed", "version": "0.0.1" }\n', 'utf8');
    await writeFile(
      path.join(root, 'package-lock.json'),
      '{ "packages": { "node_modules/demo": { "version": "1.0.0" } } }\n',
      'utf8'
    );
    process.env.COSIGN_KEY_REF = '/tmp/cosign.key';

    const logMessages: string[] = [];
    const outputPath = path.join(root, 'out', 'sbom.json');
    const { cycloneDxSignaturePath, spdxSignaturePath } = await generateSbom({
      packageJsonPath: path.join(root, 'package.json'),
      packageLockPath: path.join(root, 'package-lock.json'),
      outputPath,
      logger: (message) => logMessages.push(message)
    });

    expect(execFileMock).toHaveBeenCalledTimes(2);
    const [firstCall, secondCall] = execFileMock.mock.calls;
    assertCall<ExecFileMockArgs>(firstCall, 'cosign invocation missing');
    const [binary, args, options] = firstCall;
    expect(binary).toBe('cosign');
    expect(args).toEqual([
      'sign-blob',
      '--key',
      '/tmp/cosign.key',
      '--output-signature',
      `${outputPath}.sig`,
      outputPath
    ]);
    const execOptions: ExecFileOptions | undefined = options;
    expect(execOptions).toMatchObject({ stdio: 'pipe' });
    expect(execOptions?.env).toBeDefined();
    expect(cycloneDxSignaturePath).toBe(`${outputPath}.sig`);
    expect(logMessages).toContain(`SBOM signature written to ${outputPath}.sig`);
    const sbomRaw = await readFile(outputPath, 'utf8');
    expect(sbomRaw).toMatch(/CycloneDX/);

    assertCall<ExecFileMockArgs>(secondCall, 'second cosign invocation missing');
    const [, secondArgs] = secondCall;
    const spdxPath = path.join(root, 'out', 'sbom.spdx.json');
    expect(secondArgs).toEqual([
      'sign-blob',
      '--key',
      '/tmp/cosign.key',
      '--output-signature',
      `${spdxPath}.sig`,
      spdxPath
    ]);
    expect(spdxSignaturePath).toBe(`${spdxPath}.sig`);
    expect(logMessages).toContain(`SPDX SBOM written to ${spdxPath}`);
    expect(await readFile(spdxPath, 'utf8')).toMatch(/SPDX-2.3/);
  });

  it('derives key reference from COSIGN_PRIVATE_KEY when present', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sbom-env-'));
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, 'package.json'), '{ "name": "env", "version": "0.0.1" }\n', 'utf8');
    await writeFile(path.join(root, 'package-lock.json'), '{ "packages": {} }\n', 'utf8');
    process.env.COSIGN_PRIVATE_KEY = 'PEM_DATA';

    await generateSbom({
      packageJsonPath: path.join(root, 'package.json'),
      packageLockPath: path.join(root, 'package-lock.json'),
      outputPath: path.join(root, 'sbom.json'),
      logger: () => {}
    });

    expect(execFileMock).toHaveBeenCalledTimes(2);
    const call = execFileMock.mock.calls[0];
    assertCall<ExecFileMockArgs>(call, 'cosign invocation missing');
    const [, args] = call;
    expect(args).toEqual(
      expect.arrayContaining(['--key', 'env://COSIGN_PRIVATE_KEY', '--output-signature'])
    );
  });

  it('skips signing when no key reference is available', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sbom-nosign-'));
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, 'package.json'), '{ "name": "nosign", "version": "0.0.1" }\n', 'utf8');
    await writeFile(path.join(root, 'package-lock.json'), '{ "packages": {} }\n', 'utf8');

    const { cycloneDxSignaturePath, spdxSignaturePath } = await generateSbom({
      packageJsonPath: path.join(root, 'package.json'),
      packageLockPath: path.join(root, 'package-lock.json'),
      outputPath: path.join(root, 'sbom.json'),
      logger: () => {}
    });

    expect(cycloneDxSignaturePath).toBeUndefined();
    expect(spdxSignaturePath).toBeUndefined();
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('surfaces cosign errors with helpful context', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sbom-fail-'));
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, 'package.json'), '{ "name": "fail", "version": "0.0.1" }\n', 'utf8');
    await writeFile(path.join(root, 'package-lock.json'), '{ "packages": {} }\n', 'utf8');
    process.env.COSIGN_KEY_REF = '/tmp/cosign.key';
    execFileMock.mockImplementationOnce((_, __, ___, callback) => {
      callback(new Error('signature failure'), '', '');
    });

    await expect(
      generateSbom({
        packageJsonPath: path.join(root, 'package.json'),
        packageLockPath: path.join(root, 'package-lock.json'),
        outputPath: path.join(root, 'sbom.json'),
        logger: () => {}
      })
    ).rejects.toThrow(/cosign sign-blob failed: signature failure/);
  });
});
