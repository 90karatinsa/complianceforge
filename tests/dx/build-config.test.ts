// SPDX-License-Identifier: MIT

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

describe('build configuration overrides', () => {
  it('ensures api build emits JavaScript artefacts', () => {
    const configPath = path.resolve('api/tsconfig.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, unknown>;
    const compilerOptions = (config.compilerOptions ?? {}) as Record<string, unknown>;

    expect(compilerOptions.noEmit).toBe(false);
    expect(compilerOptions.outDir).toBe('dist');
  });

  it('ensures worker build emits JavaScript artefacts', () => {
    const configPath = path.resolve('worker/tsconfig.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, unknown>;
    const compilerOptions = (config.compilerOptions ?? {}) as Record<string, unknown>;

    expect(compilerOptions.noEmit).toBe(false);
    expect(compilerOptions.outDir).toBe('dist');
  });
});
