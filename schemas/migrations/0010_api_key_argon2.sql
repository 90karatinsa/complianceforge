-- SPDX-License-Identifier: MIT

BEGIN;

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS token_lookup_hash TEXT;

UPDATE api_keys
SET token_lookup_hash = token_hash
WHERE token_lookup_hash IS NULL;

ALTER TABLE api_keys
  ALTER COLUMN token_lookup_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_lookup_hash
  ON api_keys (token_lookup_hash);

ALTER TABLE api_keys
  DROP CONSTRAINT IF EXISTS api_keys_token_hash_key;

COMMIT;
