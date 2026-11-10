// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

import { validateLicensePublicKey } from '../../scripts/license-public-key.ts';

const toBase64Url = (buffer: Buffer): string => buffer.toString('base64url');

describe('validateLicensePublicKey', () => {
  it('accepts canonical Ed25519 SPKI public keys', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const encoded = toBase64Url(publicKey.export({ format: 'der', type: 'spki' }) as Buffer);

    expect(validateLicensePublicKey(encoded)).toBe(encoded);
  });

  it('rejects malformed base64url strings', () => {
    expect(() => validateLicensePublicKey('***INVALID***')).toThrow(/base64url/i);
  });

  it('rejects keys that are not Ed25519 SPKI blobs', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const encoded = toBase64Url(pem);

    expect(() => validateLicensePublicKey(encoded)).toThrow(/Ed25519/);
  });

  it('requires canonical base64url encoding', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const der = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const padded = der.toString('base64');
    const nonCanonical = padded.replace(/\+/g, '-').replace(/\//g, '_');

    expect(() => validateLicensePublicKey(nonCanonical)).toThrow(/base64url/i);
  });
});
