// SPDX-License-Identifier: MIT

import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { runLicenseCompliance } from '../../scripts/license-compliance.ts';

async function createTempProject(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'license-'));
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'src', 'index.ts'), `${'// SPDX-License-Identifier: MIT\n'}export const value = 1;\n`, 'utf8');
  const lock = {
    name: 'demo',
    lockfileVersion: 3,
    packages: {
      '': { name: 'demo', version: '1.0.0' },
      'node_modules/alpha': { name: 'alpha', version: '1.0.0', license: 'MIT' },
      'node_modules/@scope/beta': { name: '@scope/beta', version: '2.0.0', license: 'Apache-2.0' }
    }
  };
  await writeFile(path.join(root, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`, 'utf8');
  return root;
}

describe('runLicenseCompliance', () => {
  it('passes when headers and dependency licenses are compliant', async () => {
    const root = await createTempProject();
    await expect(runLicenseCompliance({ rootDir: root, logger: () => {} })).resolves.toBeUndefined();
  });

  it('fails when a proprietary header is missing', async () => {
    const root = await createTempProject();
    await writeFile(path.join(root, 'src', 'missing.ts'), 'export const missing = true;\n', 'utf8');

    await expect(runLicenseCompliance({ rootDir: root, logger: () => {} })).rejects.toThrow('compliance issue(s) detected');
  });

  it('fails when a dependency uses a forbidden license', async () => {
    const root = await createTempProject();
    const lockPath = path.join(root, 'package-lock.json');
    const lockContent = await readFile(lockPath, 'utf8');
    const parsed = JSON.parse(lockContent) as Record<string, unknown>;
    const packages = parsed.packages as Record<string, Record<string, unknown>>;
    packages['node_modules/alpha'].license = 'GPL-3.0';
    await writeFile(lockPath, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');

    await expect(runLicenseCompliance({ rootDir: root, logger: () => {} })).rejects.toThrow('compliance issue(s) detected');
  });
});
