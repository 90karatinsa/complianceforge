// SPDX-License-Identifier: MIT

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

describe('legal and operational documentation', () => {
  it('documents the MIT licence and installer acceptance', () => {
    const eula = readFileSync(path.resolve('docs/EULA.md'), 'utf8');
    expect(eula).toMatch(/MIT lisansı/i);
    expect(eula).toMatch(/--accept-eula/);
    expect(eula).toMatch(/offline doğrulama/i);
  });

  it('covers offline update verification and anti-rollback steps', () => {
    const offlineGuide = readFileSync(path.resolve('docs/offline-updates.md'), 'utf8');
    expect(offlineGuide).toMatch(/Ed25519/i);
    expect(offlineGuide).toMatch(/minimum_downgrade_version/i);
    expect(offlineGuide).not.toMatch(/minimum_version/);
    expect(offlineGuide).toMatch(/offline doğrulanması/i);
    expect(offlineGuide).toMatch(/npm run tsx -- scripts\/feed-import\.ts verify/);
    expect(offlineGuide).toMatch(/license:status -- --accept-eula/);
    expect(offlineGuide).toMatch(/\/Library\/Application Support\/Atlas SCA\/eula\.accepted/);
    expect(offlineGuide).toMatch(/msiexec \/i AtlasSCA\.msi ALTERA_EULA_ACCEPTED=1/);
    expect(offlineGuide).toMatch(/icacls '%ProgramData%\\Atlas SCA\\eula\.accepted'/);

    const runbook = readFileSync(path.resolve('docs/runbook.md'), 'utf8');
    expect(runbook).toMatch(/msiexec \/i AtlasSCA\.msi ALTERA_EULA_ACCEPTED=1/);
    expect(runbook).toMatch(/%ProgramData%\\Atlas SCA\\eula\.accepted/);
  });

  it('ensures license documentation links to the dedicated EULA file', () => {
    const licenseDoc = readFileSync(path.resolve('docs/license.md'), 'utf8');
    expect(licenseDoc).toContain('[EULA metnini](./EULA.md)');
  });
});
