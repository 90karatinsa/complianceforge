// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import { deriveLicenseObligations } from '../worker/src/license-obligations.ts';

describe('deriveLicenseObligations', () => {
  it('returns notice and attribution for permissive licenses', () => {
    const obligations = deriveLicenseObligations({ spdxId: 'MIT' });

    expect(obligations).toEqual({ notice: true, attribution: true });
  });

  it('includes source and patent requirements for strong copyleft licenses', () => {
    const obligations = deriveLicenseObligations({ spdxId: 'GPL-3.0-only' });

    expect(obligations).toEqual({
      notice: true,
      source: true,
      patent: true,
      custom: ['copyleft']
    });
  });

  it('marks custom license references for review', () => {
    const obligations = deriveLicenseObligations({ spdxId: 'LicenseRef-Custom' });

    expect(obligations).toEqual({
      notice: true,
      attribution: true,
      custom: ['LICENSEREF-CUSTOM']
    });
  });

  it('falls back to defaults when no rule matches', () => {
    const obligations = deriveLicenseObligations({ spdxId: 'Unknown-1.0' });

    expect(obligations).toEqual({});
  });
});
