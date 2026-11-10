// SPDX-License-Identifier: MIT

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';

const AES_ALGORITHM = 'aes-256-gcm';
export const WEBHOOK_SECRET_IV_LENGTH = 12; // 96-bit nonce per RFC 5116

export interface EncryptedWebhookSecret {
  readonly ciphertext: Buffer;
  readonly iv: Buffer;
  readonly authTag: Buffer;
  readonly lastFour: string | null;
}

export function encryptWebhookSecret(plaintext: string, key: Buffer): EncryptedWebhookSecret {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('Webhook secret key must be a 32-byte buffer.');
  }

  const iv = randomBytes(WEBHOOK_SECRET_IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const lastFour = plaintext.length >= 4 ? plaintext.slice(-4) : plaintext || null;

  return { ciphertext, iv, authTag, lastFour };
}

export function decryptWebhookSecret(
  ciphertext: Buffer | null,
  iv: Buffer | null,
  authTag: Buffer | null,
  key: Buffer
): string | null {
  if (!ciphertext || !iv || !authTag) {
    return null;
  }

  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('Webhook secret key must be a 32-byte buffer.');
  }

  const decipher = createDecipheriv(AES_ALGORITHM, key, iv, { authTagLength: authTag.length });
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}
