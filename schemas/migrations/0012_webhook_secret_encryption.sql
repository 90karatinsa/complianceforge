BEGIN;

ALTER TABLE webhooks
  ADD COLUMN IF NOT EXISTS secret_ciphertext BYTEA,
  ADD COLUMN IF NOT EXISTS secret_iv BYTEA,
  ADD COLUMN IF NOT EXISTS secret_auth_tag BYTEA,
  ADD COLUMN IF NOT EXISTS secret_last_four TEXT;

UPDATE webhooks
  SET secret_last_four = RIGHT(secret, 4)
  WHERE secret IS NOT NULL AND secret_last_four IS NULL;

UPDATE webhooks
  SET secret = NULL
  WHERE secret IS NOT NULL;

COMMIT;
