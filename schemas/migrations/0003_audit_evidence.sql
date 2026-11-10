BEGIN;

CREATE TABLE IF NOT EXISTS audit_log_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  actor_type TEXT NOT NULL,
  actor_identifier TEXT,
  event_type TEXT NOT NULL,
  event_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  event_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS evidence_packs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  storage_path TEXT,
  manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
  signature TEXT,
  hash_algorithm TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_events_tenant_id ON audit_log_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_events_project_id ON audit_log_events (project_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_events_scan_id ON audit_log_events (scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_events_created_at ON audit_log_events (created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_tenant_id ON evidence_packs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_scan_id ON evidence_packs (scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_packs_scan_unique ON evidence_packs (tenant_id, scan_id) WHERE scan_id IS NOT NULL;

COMMIT;
