// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
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
const ED25519_SPKI_TOTAL_BYTES = 44;

function decodeBase64Url(value: string, field: string): Buffer {
  try {
    const decoded = Buffer.from(value, 'base64url');
    const canonical = decoded.toString('base64url');

    if (canonical !== value) {
      throw new Error('Value must use canonical base64url encoding.');
    }

    return decoded;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${field} must be valid base64url data: ${message}`);
  }
}

export function validateLicensePublicKey(value: string, field = 'LICENSE_PUBLIC_KEY'): string {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error(`${field} must be configured and non-empty.`);
  }

  if (!BASE64URL_PATTERN.test(trimmed)) {
    throw new Error(`${field} must be a base64url-encoded DER public key string.`);
  }

  const decoded = decodeBase64Url(trimmed, field);

  if (decoded.length !== ED25519_SPKI_TOTAL_BYTES) {
    throw new Error(`${field} must decode to a 44 byte Ed25519 public key.`);
  }

  if (!decoded.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error(`${field} must be a DER-encoded Ed25519 SPKI public key.`);
  }

  return trimmed;
}
