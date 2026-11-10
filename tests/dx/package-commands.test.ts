// SPDX-License-Identifier: MIT

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

describe('packaging developer experience commands', () => {
  it('exposes per-platform packaging scripts in package.json', () => {
    const pkgPath = path.resolve('package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.dev).toBe('tsx scripts/dev.ts');
    expect(pkg.scripts?.['package:windows']).toBe('tsx scripts/package/windows-msi.ts');
    expect(pkg.scripts?.['package:macos']).toBe('tsx scripts/package/macos-pkg.ts');
    expect(pkg.scripts?.['package:deb']).toBe('tsx scripts/package/deb.ts');
    expect(pkg.scripts?.['package:all']).toBe('npm run package:windows && npm run package:macos && npm run package:deb');
  });

  it('adds Makefile aliases for packaging commands', () => {
    const makefile = readFileSync(path.resolve('Makefile'), 'utf8');
    expect(makefile).toContain('package-windows:');
    expect(makefile).toContain('npm run package:windows');
    expect(makefile).toContain('package-macos:');
    expect(makefile).toContain('npm run package:macos');
    expect(makefile).toContain('package-deb:');
    expect(makefile).toContain('npm run package:deb');
    expect(makefile).toContain('package-all:');
    expect(makefile).toContain('npm run package:all');
    expect(makefile).toContain('dev:');
    expect(makefile).toContain('npm run dev');
  });

  it('documents the compliance shortcut in Makefile and quickstart guide', () => {
    const makefile = readFileSync(path.resolve('Makefile'), 'utf8');
    expect(makefile).toMatch(/compliance:\n\s+npm run compliance/);

    const quickstart = readFileSync(path.resolve('docs/quickstart.md'), 'utf8');
    expect(quickstart).toMatch(/make compliance/);
    expect(quickstart).toMatch(/npm run compliance/);
    expect(quickstart).toMatch(/npm run dev/);
    expect(quickstart).toMatch(/make dev/);
  });
});
