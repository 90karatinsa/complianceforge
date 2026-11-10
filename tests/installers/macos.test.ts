// SPDX-License-Identifier: MIT

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { planMacBuild } from '../../scripts/package/macos-pkg.ts';

let cleanup: string[] = [];

afterEach(() => {
  for (const entry of cleanup) {
    rmSync(entry, { recursive: true, force: true });
  }
  cleanup = [];
});

describe('macOS installer packaging', () => {
  it('embeds license metadata in Distribution.xml', () => {
    const distributionPath = path.resolve('deploy/installers/macos/Distribution.xml');
    const contents = readFileSync(distributionPath, 'utf8');
    expect(contents).toContain('<license file="Resources/license.txt"');
    expect(contents).toContain('hostArchitectures="x86_64,arm64"');
    expect(contents).toContain('#AtlasSCA.component.pkg');
  });

  it('prepares pkgbuild/productbuild/appdmg commands with resolved paths', () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'atlas-macos-plan-'));
    cleanup.push(tempDir);
    const plan = planMacBuild({
      version: '1.5.0',
      distDir: tempDir,
      pkgbuildPath: '/usr/bin/pkgbuild',
      productbuildPath: '/usr/bin/productbuild',
      appdmgPath: '/usr/local/bin/appdmg'
    });
    expect(plan.pkgbuild.command).toBe('/usr/bin/pkgbuild');
    expect(plan.pkgbuild.args).toContain('--identifier');
    expect(plan.pkgbuild.args).toContain('com.alterra.atlassca');
    expect(plan.pkgbuild.args).toContain('1.5.0');
    expect(plan.pkgbuild.args).toContain('--scripts');
    expect(plan.pkgbuild.args).toContain(path.resolve('deploy/installers/macos/Scripts'));
    expect(plan.productbuild.command).toBe('/usr/bin/productbuild');
    expect(plan.productbuild.args).toContain(path.resolve('deploy/installers/macos/Distribution.xml'));
    expect(plan.productbuild.args).toContain(plan.pkgPath);
    expect(plan.appdmg.command).toBe('/usr/local/bin/appdmg');
    expect(plan.appdmg.args[0]).toBe(path.join(tempDir, 'staging', 'appdmg.json'));
    expect(plan.appdmg.args[1]).toBe(path.join(tempDir, 'AtlasSCA-1.5.0.dmg'));
    expect(plan.appdmgConfigContents).not.toContain('{{PKG_PATH}}');
    expect(plan.appdmgConfigContents).toContain(path.join(tempDir, 'AtlasSCA-1.5.0.pkg'));
    expect(plan.checksumPath).toBe(path.join(tempDir, 'AtlasSCA-1.5.0.dmg.sha256'));
  });

  it('enforces EULA acceptance during macOS preinstall', () => {
    const scriptPath = path.resolve('deploy/installers/macos/Scripts/preinstall');
    const contents = readFileSync(scriptPath, 'utf8');
    expect(contents).toMatchInlineSnapshot(`"#!/bin/sh\nset -eu\n\nEULA_FLAG_FILE=\"/Library/Application Support/Atlas SCA/eula.accepted\"\n\nif [ \"\${ALTERA_EULA_ACCEPTED:-0}\" = \"1\" ]; then\n  exit 0\nfi\n\nif [ -L \"$EULA_FLAG_FILE\" ]; then\n  cat <<USAGE >&2\nAtlas SCA requires acceptance of the ComplianceForge lisans (MIT) before installation.\nThe acceptance marker must be a regular file with 0600 permissions (no symlinks).\nRemove the symlink and recreate the marker with owner-only access:\n  sudo rm -f \"$EULA_FLAG_FILE\"\n  sudo install -d -m 755 \"/Library/Application Support/Atlas SCA\"\n  sudo install -m 600 /dev/null \"$EULA_FLAG_FILE\"\nUSAGE\n  exit 1\nfi\n\nif [ -f \"$EULA_FLAG_FILE\" ]; then\n  perms=\"$(stat -f \"%Lp\" \"$EULA_FLAG_FILE\")\"\n  if [ \"$perms\" = \"600\" ]; then\n    exit 0\n  fi\n  cat <<USAGE >&2\nAtlas SCA requires acceptance of the ComplianceForge lisans (MIT) before installation.\nExisting acceptance markers must be 0600 (owner read/write only).\nFix the permissions before retrying the installer:\n  sudo chmod 600 \"$EULA_FLAG_FILE\"\nUSAGE\n  exit 1\nfi\n\ncat <<USAGE >&2\nAtlas SCA requires acceptance of the ComplianceForge lisans (MIT) before installation.\nSet ALTERA_EULA_ACCEPTED=1 when invoking the installer or create the acceptance marker:\n  sudo install -d -m 755 \"/Library/Application Support/Atlas SCA\"\n  sudo install -m 600 /dev/null \"$EULA_FLAG_FILE\"\nUSAGE\n\nexit 1\n"`);
  });
});
