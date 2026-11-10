// SPDX-License-Identifier: MIT

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { planWindowsBuild } from '../../scripts/package/windows-msi.ts';

let cleanupPaths: string[] = [];

afterEach(() => {
  for (const entry of cleanupPaths) {
    rmSync(entry, { recursive: true, force: true });
  }
  cleanupPaths = [];
});

describe('windows installer assets', () => {
  it('references the EULA, requires an operator token, and omits ARP icon when unavailable', () => {
    const wxsPath = path.resolve('deploy/installers/windows/Product.wxs');
    const contents = readFileSync(wxsPath, 'utf8');
    expect(contents).toContain('WixUILicenseRtf');
    expect(contents).toContain('$(var.EulaPath)');
    expect(contents).toContain('ARPCONTACT');
    expect(contents).toContain('OFFLINE_GATE_EXPECTED');
    expect(contents).toContain('OFFLINE_CHECK');
    expect(contents).toContain('OFFLINE_CHECK <> ""');
    expect(contents).toContain('xmlns:util="http://schemas.microsoft.com/wix/UtilExtension"');
    expect(contents).toContain('Property Id="EULA_ACCEPTED_ENV"');
    expect(contents).toContain('Environment Id="Env.AlterraEulaAccepted"');
    expect(contents).toContain('util:FileSearch');
    expect(contents).toContain('Name="eula.accepted"');
    expect(contents).toContain('%ProgramData%\\Atlas SCA\\eula.accepted');
    expect(contents).not.toContain('ARPPRODUCTICON');
    expect(contents).not.toContain('<Icon');
  });

  it('defines EULA constant and offline expectation in Product.wixproj', () => {
    const projectPath = path.resolve('deploy/installers/windows/Product.wixproj');
    const project = readFileSync(projectPath, 'utf8');
    expect(project).toContain('License.rtf');
    expect(project).toContain('PayloadDir=$(ProjectDir)payload');
    expect(project).toContain('OfflineGateExpectation=055356bab4da9887f07289591f0f94f7edc632e09cef70cc9d3a0761b644b356');
  });

  it('builds a plan with candle/light/sign commands, hashed offline expectation, and checksum output', () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'atlas-windows-plan-'));
    cleanupPaths.push(tempDir);
    const plan = planWindowsBuild({
      version: '1.2.3',
      candlePath: 'candle.exe',
      lightPath: 'light.exe',
      signtoolPath: 'signtool.exe',
      certificatePath: 'certs\\atlas.pfx',
      timestampUrl: 'http://tsa.invalid',
      distDir: tempDir,
      offlineToken: 'custom-offline-token'
    });
    expect(plan.outputMsi).toContain('AtlasSCA-1.2.3.msi');
    expect(plan.candle.command).toBe('candle.exe');
    expect(plan.candle.args).toContain(
      '-dOfflineGateExpectation=4aaac51e259b5dafad66ee61350ef8d3d8a003035c69fae9aa65abd71e70d1e3'
    );
    expect(plan.light.command).toBe('light.exe');
    expect(plan.light.args).toContain('WixUIExtension');
    expect(plan.light.args).toContain('WixUtilExtension');
    expect(plan.sign).toBeDefined();
    expect(plan.sign?.command).toBe('signtool.exe');
    expect(plan.sign?.args).toContain('/f');
    expect(plan.sign?.args).toContain('certs\\atlas.pfx');
    expect(plan.sign?.args).toContain('/tr');
    expect(plan.checksumPath).toBe(`${plan.outputMsi}.sha256`);
    expect(plan.offlineGateExpectation).toBe(
      '4aaac51e259b5dafad66ee61350ef8d3d8a003035c69fae9aa65abd71e70d1e3'
    );
  });
});
