// SPDX-License-Identifier: MIT

import { beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('k6/http', () => ({
  default: {},
  get: vi.fn()
}));

vi.mock('k6', () => ({
  check: vi.fn(),
  sleep: vi.fn()
}));
beforeAll(() => {
  (globalThis as typeof globalThis & { __ENV?: Record<string, string> }).__ENV = {};
});

describe('performance thresholds', () => {
  it('enforces premium latency and error budgets', async () => {
    const { options } = await import('../../scripts/perf/load.k6.js');
    expect(options.thresholds?.http_req_duration).toEqual(['p(95)<250']);
    expect(options.thresholds?.http_req_failed).toEqual(['rate<0.005']);
  });
});
