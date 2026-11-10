// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';

export const TEST_LICENSE_ID = 'test-license';

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30,
  0x2a,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x03,
  0x21,
  0x00
]);

export function createEd25519PublicKey(fill = 0): string {
  const keyMaterial = Buffer.alloc(32, fill & 0xff);
  return Buffer.concat([ED25519_SPKI_PREFIX, keyMaterial]).toString('base64url');
}

export const TEST_LICENSE_PUBLIC_KEY = createEd25519PublicKey(0);

export type LicenseStatusOverrides = {
  readonly licenseId?: string;
  readonly status?: 'active' | 'expired' | 'revoked';
  readonly expiresAt?: string;
  readonly features?: readonly string[];
  readonly lastValidatedAt?: string;
  readonly warnings?: readonly string[];
};

export function createActiveLicenseStatus(overrides?: LicenseStatusOverrides) {
  return {
    licenseId: overrides?.licenseId ?? TEST_LICENSE_ID,
    status: overrides?.status ?? ('active' as const),
    expiresAt: overrides?.expiresAt ?? new Date('2099-12-31T23:59:59.000Z').toISOString(),
    features: overrides?.features ?? ['scan:execute'],
    lastValidatedAt: overrides?.lastValidatedAt ?? new Date('2099-01-01T00:00:00.000Z').toISOString(),
    warnings: overrides?.warnings ?? ([] as const)
  };
}

export const createLicenseStatus = createActiveLicenseStatus;

export function createLicenseStatusProvider(overrides?: LicenseStatusOverrides) {
  const status = createActiveLicenseStatus(overrides);
  return async () => status;
}
