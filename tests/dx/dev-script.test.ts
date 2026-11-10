// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const spawnMock = vi.fn(() => ({
  on: vi.fn(),
  kill: vi.fn(),
  killed: false
}));

vi.mock('node:child_process', () => ({
  spawn: spawnMock
}));

describe('dev process launcher', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  beforeEach(() => {
    spawnMock.mockClear();
    process.env.NODE_ENV = 'production';
  });

  afterEach(() => {
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it('spawns API and worker dev scripts with NODE_ENV=development', async () => {
    const { startDevProcesses } = await import('../../scripts/dev.ts');

    startDevProcesses();

    expect(spawnMock).toHaveBeenCalledTimes(2);
    for (const call of spawnMock.mock.calls) {
      const [, , options] = call;
      expect(options?.env?.NODE_ENV).toBe('development');
      expect(options?.env?.NODE_ENV).not.toBe('production');
    }
  });
});
