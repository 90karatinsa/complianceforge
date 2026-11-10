// SPDX-License-Identifier: MIT

export interface LicenseObligations {
  readonly notice?: boolean;
  readonly attribution?: boolean;
  readonly source?: boolean;
  readonly patent?: boolean;
  readonly custom?: string[];
}

interface ObligationRule {
  readonly notice?: boolean;
  readonly attribution?: boolean;
  readonly source?: boolean;
  readonly patent?: boolean;
  readonly custom?: string[];
}

const SPDX_RULES: Record<string, ObligationRule> = {
  'MIT': { notice: true, attribution: true },
  'BSD-2-CLAUSE': { notice: true, attribution: true },
  'BSD-3-CLAUSE': { notice: true, attribution: true },
  'APACHE-2.0': { notice: true, attribution: true, patent: true },
  'ISC': { notice: true, attribution: true },
  'MPL-2.0': { notice: true, source: true },
  'GPL-3.0-ONLY': { notice: true, source: true, patent: true, custom: ['copyleft'] },
  'GPL-3.0-OR-LATER': { notice: true, source: true, patent: true, custom: ['copyleft'] },
  'LGPL-3.0-ONLY': { notice: true, source: true, custom: ['weak-copyleft'] },
  'LGPL-3.0-OR-LATER': { notice: true, source: true, custom: ['weak-copyleft'] },
  'AGPL-3.0-ONLY': { notice: true, source: true, patent: true, custom: ['network-copyleft'] },
  'AGPL-3.0-OR-LATER': { notice: true, source: true, patent: true, custom: ['network-copyleft'] },
  'CDDL-1.0': { notice: true, source: true },
  'EPL-2.0': { notice: true, source: true },
  'CC-BY-4.0': { notice: true, attribution: true }
};

const DEFAULT_OBLIGATIONS: LicenseObligations = {};

function normalizeSpdx(value: string | null | undefined): string | null {
  if (!value) {
    return null;
  }

  return value.trim().toUpperCase();
}

export function deriveLicenseObligations(input: {
  readonly spdxId?: string | null;
  readonly licenseExpression?: string | null;
}): LicenseObligations {
  const normalizedId = normalizeSpdx(input.spdxId);

  if (normalizedId && SPDX_RULES[normalizedId]) {
    return SPDX_RULES[normalizedId];
  }

  if (normalizedId?.startsWith('LICENSEREF-')) {
    return {
      notice: true,
      attribution: true,
      custom: [normalizedId]
    } satisfies LicenseObligations;
  }

  const expression = normalizeSpdx(input.licenseExpression);

  if (expression && SPDX_RULES[expression]) {
    return SPDX_RULES[expression];
  }

  return DEFAULT_OBLIGATIONS;
}
