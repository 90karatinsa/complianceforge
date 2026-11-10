BEGIN;

CREATE TABLE IF NOT EXISTS notice_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  template TEXT NOT NULL,
  document TEXT NOT NULL,
  component_count INTEGER NOT NULL,
  signature_hash TEXT NOT NULL,
  signoff_name TEXT NOT NULL,
  signoff_email TEXT,
  signoff_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  feed_version TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notice_versions_tenant_id ON notice_versions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_notice_versions_project_id ON notice_versions (project_id);
CREATE INDEX IF NOT EXISTS idx_notice_versions_scan_id ON notice_versions (scan_id);
CREATE INDEX IF NOT EXISTS idx_notice_versions_created_at ON notice_versions (created_at DESC);

COMMIT;
