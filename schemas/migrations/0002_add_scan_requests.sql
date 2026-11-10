BEGIN;

CREATE TABLE IF NOT EXISTS scan_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, key_hash)
);

CREATE INDEX IF NOT EXISTS idx_scan_requests_tenant_id ON scan_requests (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_requests_scan_id ON scan_requests (scan_id) WHERE scan_id IS NOT NULL;

CREATE OR REPLACE FUNCTION delete_scan_request_for_scan()
RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM scan_requests WHERE scan_id = OLD.id;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_scan_requests_cleanup ON scans;
CREATE TRIGGER trg_scan_requests_cleanup
AFTER DELETE ON scans
FOR EACH ROW
EXECUTE FUNCTION delete_scan_request_for_scan();

COMMIT;
