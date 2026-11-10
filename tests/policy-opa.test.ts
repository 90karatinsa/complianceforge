// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluatePolicy, type PolicyRules, __unsafeResetOpaBundleCache } from '../worker/src/policy-opa.js';
import type { ScannerResult } from '../worker/src/scanners.js';

const baseScannerResult: ScannerResult = {
  packages: [
    { name: 'left-pad', version: '1.0.0', ecosystem: 'npm', purl: 'pkg:npm/left-pad@1.0.0' }
  ],
  licenses: [{ path: 'LICENSE', spdxId: 'GPL-3.0-ONLY', packageName: 'left-pad' }],
  vulnerabilities: [
    {
      package: { name: 'left-pad', version: '1.0.0', ecosystem: 'npm', purl: 'pkg:npm/left-pad@1.0.0' },
      vulnerabilities: [
        {
          id: 'CVE-2024-0001',
          summary: 'Example',
          severity: [{ score: '9.8' }]
        }
      ]
    }
  ],
  bom: {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { timestamp: '2024-01-01T00:00:00.000Z', tools: [] },
    components: []
  }
};

describe('policy OPA evaluation', () => {
  const originalAllowNetworkFetch = process.env.ALLOW_NETWORK_FETCH;
  beforeEach(() => {
    __unsafeResetOpaBundleCache();
    vi.useRealTimers();
    if (originalAllowNetworkFetch === undefined) {
      delete process.env.ALLOW_NETWORK_FETCH;
    } else {
      process.env.ALLOW_NETWORK_FETCH = originalAllowNetworkFetch;
    }
  });
  afterEach(() => {
    if (originalAllowNetworkFetch === undefined) {
      delete process.env.ALLOW_NETWORK_FETCH;
    } else {
      process.env.ALLOW_NETWORK_FETCH = originalAllowNetworkFetch;
    }
  });
  it('evaluates static license rules', async () => {
    const rules: PolicyRules = {
      denied_spdx: ['GPL-3.0-ONLY']
    };

    const result = await evaluatePolicy({ rules, scannerResult: baseScannerResult });
    expect(result.result).toBe('fail');
    expect(result.reasons).toEqual(expect.arrayContaining([expect.stringMatching(/GPL-3.0-ONLY/u)]));
  });

  it('applies inline OPA decisions', async () => {
    const rules: PolicyRules = {
      opa: {
        decisions: [
          {
            effect: 'deny',
            reason: 'Denied by inline policy.',
            match: { component_purl: 'pkg:npm/left-pad@1.0.0' }
          }
        ]
      }
    };

    const result = await evaluatePolicy({ rules, scannerResult: baseScannerResult });
    expect(result.result).toBe('fail');
    expect(result.reasons).toContain('Denied by inline policy.');
  });

  it('fetches bundle decisions when configured', async () => {
    process.env.ALLOW_NETWORK_FETCH = 'true';
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        decisions: [
          {
            effect: 'deny',
            reason: 'Bundle decision deny.',
            match: { spdx: 'GPL-3.0-ONLY' }
          }
        ]
      })
    });

    const rules: PolicyRules = {
      opa: {
        bundle_url: 'https://policy.example.com/bundle.json'
      }
    };

    const result = await evaluatePolicy({ rules, scannerResult: baseScannerResult, fetchImpl });
    expect(fetchImpl).toHaveBeenCalled();
    expect(result.result).toBe('fail');
    expect(result.reasons).toContain('Bundle decision deny.');
  });

  it('rejects bundle downloads when ALLOW_NETWORK_FETCH is disabled', async () => {
    process.env.ALLOW_NETWORK_FETCH = 'no';
    const fetchImpl = vi.fn();

    await expect(
      evaluatePolicy({
        rules: { opa: { bundle_url: 'https://policy.example.com/bundle.json' } },
        scannerResult: baseScannerResult,
        fetchImpl
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects bundle downloads when ALLOW_NETWORK_FETCH is unset', async () => {
    delete process.env.ALLOW_NETWORK_FETCH;
    const fetchImpl = vi.fn();

    await expect(
      evaluatePolicy({
        rules: { opa: { bundle_url: 'https://policy.example.com/bundle.json' } },
        scannerResult: baseScannerResult,
        fetchImpl
      })
    ).rejects.toThrow(/ALLOW_NETWORK_FETCH/);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('reuses cached bundle decisions until the TTL expires', async () => {
    vi.useFakeTimers();
    process.env.ALLOW_NETWORK_FETCH = 'true';

    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        decisions: [
          {
            effect: 'deny',
            reason: 'Cached decision.',
            match: { spdx: 'GPL-3.0-ONLY' }
          }
        ]
      })
    });

    const rules: PolicyRules = {
      opa: {
        bundle_url: 'https://policy.example.com/bundle.json',
        cache_ttl_seconds: 5
      }
    };

    const first = await evaluatePolicy({ rules, scannerResult: baseScannerResult, fetchImpl });
    expect(first.result).toBe('fail');
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const second = await evaluatePolicy({ rules, scannerResult: baseScannerResult, fetchImpl });
    expect(second.result).toBe('fail');
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(6_000);

    const third = await evaluatePolicy({ rules, scannerResult: baseScannerResult, fetchImpl });
    expect(third.result).toBe('fail');
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

  it('rejects non-HTTPS bundle URLs', async () => {
    process.env.ALLOW_NETWORK_FETCH = 'true';
    const fetchImpl = vi.fn();

    await expect(
      evaluatePolicy({
        rules: { opa: { bundle_url: 'http://policy.example.com/bundle.json' } },
        scannerResult: baseScannerResult,
        fetchImpl
      })
    ).rejects.toThrow(/HTTPS/);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects invalid bundle URLs', async () => {
    process.env.ALLOW_NETWORK_FETCH = 'true';
    const fetchImpl = vi.fn();

    await expect(
      evaluatePolicy({
        rules: { opa: { bundle_url: '::not-a-url::' } },
        scannerResult: baseScannerResult,
        fetchImpl
      })
    ).rejects.toThrow(/valid HTTPS URL/);

    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

