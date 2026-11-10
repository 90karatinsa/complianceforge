// SPDX-License-Identifier: MIT

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { buildDebInstaller, planDebBuild } from '../../scripts/package/deb.ts';

type CommandPlan = ReturnType<typeof planDebBuild>['dpkg'];

let toDelete: string[] = [];

afterEach(() => {
  for (const entry of toDelete) {
    rmSync(entry, { recursive: true, force: true });
  }
  toDelete = [];
});

describe('Debian packaging assets', () => {
  it('templates include EULA enforcement and offline messaging', () => {
    const controlTemplate = readFileSync('deploy/installers/deb/DEBIAN/control', 'utf8');
    expect(controlTemplate).toContain('Version: @VERSION@');
    expect(controlTemplate).toContain('offline doğrulayan');
    const preinst = readFileSync('deploy/installers/deb/DEBIAN/preinst', 'utf8');
    expect(preinst).toContain('ALTERA_EULA_ACCEPTED');
    expect(preinst).toContain('lisans (MIT) kabulünü gerektirir');
  });

  it('generates staging tree with hydrated control file and dpkg-deb invocation', async () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'atlas-deb-plan-'));
    toDelete.push(tempDir);
    const executed: CommandPlan[] = [];
    const output = await buildDebInstaller({
      version: '2.0.0',
      distDir: tempDir,
      dpkgDebPath: '/usr/bin/dpkg-deb',
      runner: (descriptor) => {
        executed.push(descriptor);
        const outputTarget = descriptor.args.at(-1);
        if (outputTarget) {
          writeFileSync(outputTarget, 'deb');
        }
      }
    });
    expect(output).toBe(path.join(tempDir, 'atlas-sca_2.0.0_amd64.deb'));
    expect(executed).toHaveLength(1);
    expect(executed[0].command).toBe('/usr/bin/dpkg-deb');
    expect(executed[0].args).toContain('--root-owner-group');

    const stagingDir = path.join(tempDir, 'atlas-sca_2.0.0');
    const control = readFileSync(path.join(stagingDir, 'DEBIAN', 'control'), 'utf8');
    expect(control).toContain('Version: 2.0.0');
    expect(control).toMatch(/offline doğrula/i);
    const stagingPreinst = readFileSync(path.join(stagingDir, 'DEBIAN', 'preinst'), 'utf8');
    expect(stagingPreinst).toContain('ALTERA_EULA_ACCEPTED');
    const checksumPath = `${output}.sha256`;
    const checksumContents = readFileSync(checksumPath, 'utf8');
    expect(checksumContents).toMatch(/^[0-9a-f]{64}  atlas-sca_2.0.0_amd64\.deb$/m);
  });

  it('exposes checksum path on the build plan', () => {
    const plan = planDebBuild({ version: '3.1.4', distDir: '/tmp/out' });
    expect(plan.outputPath).toBe('/tmp/out/atlas-sca_3.1.4_amd64.deb');
    expect(plan.checksumPath).toBe('/tmp/out/atlas-sca_3.1.4_amd64.deb.sha256');
  });

  it('restores SOURCE_DATE_EPOCH environment variable after building', async () => {
    const prior = process.env.SOURCE_DATE_EPOCH;
    const tempDirWithEnv = mkdtempSync(path.join(os.tmpdir(), 'atlas-deb-env-'));
    const tempDirNoEnv = mkdtempSync(path.join(os.tmpdir(), 'atlas-deb-noenv-'));
    toDelete.push(tempDirWithEnv, tempDirNoEnv);

    const runner = (descriptor: CommandPlan) => {
      const outputTarget = descriptor.args.at(-1);
      if (outputTarget) {
        writeFileSync(outputTarget, 'deb');
      }
    };

    try {
      process.env.SOURCE_DATE_EPOCH = '424242';
      await buildDebInstaller({
        version: '4.2.0',
        distDir: tempDirWithEnv,
        dpkgDebPath: '/usr/bin/dpkg-deb',
        runner
      });
      expect(process.env.SOURCE_DATE_EPOCH).toBe('424242');

      delete process.env.SOURCE_DATE_EPOCH;
      await buildDebInstaller({
        version: '4.3.0',
        distDir: tempDirNoEnv,
        dpkgDebPath: '/usr/bin/dpkg-deb',
        runner
      });
      expect(process.env.SOURCE_DATE_EPOCH).toBeUndefined();
    } finally {
      if (prior === undefined) {
        delete process.env.SOURCE_DATE_EPOCH;
      } else {
        process.env.SOURCE_DATE_EPOCH = prior;
      }
    }
  });
});
