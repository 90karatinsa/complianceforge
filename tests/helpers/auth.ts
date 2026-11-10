// SPDX-License-Identifier: MIT

import { createHash } from 'node:crypto';

import { TEST_LICENSE_PUBLIC_KEY } from './license.ts';

export const TEST_API_KEY = 'test-api-key';
export const TEST_API_KEY_ID = 'test-api-key-id';
export const TEST_API_KEY_SALT = 'test-salt';
export const TEST_API_KEY_LOOKUP_HASH = createHash('sha256')
  .update(`${TEST_API_KEY_SALT}:${TEST_API_KEY}`)
  .digest('hex');
export const TEST_API_KEY_DIGEST =
  '$argon2id$v=19$m=15360,t=2,p=1$7m5oxjvmKYeb+/TC/caWsA$6XEJL3kG5C4Q6FqEwT+YYXwJgM6fcyFFI6ZXSmxP0gA';

if (!process.env.LICENSE_PUBLIC_KEY) {
  process.env.LICENSE_PUBLIC_KEY = TEST_LICENSE_PUBLIC_KEY;
}

export function createAuthMocks(tenantId: string, roles: string[] = ['Admin']) {
  return {
    headers: { authorization: `Bearer ${TEST_API_KEY}` },
    lookupApiKey: (hash: string) =>
      Promise.resolve(
        hash === TEST_API_KEY_LOOKUP_HASH
          ? {
              id: TEST_API_KEY_ID,
              tenant_id: tenantId,
              permissions: roles,
              token_hash: TEST_API_KEY_DIGEST,
              token_lookup_hash: TEST_API_KEY_LOOKUP_HASH
            }
          : null
      )
  } as const;
}
