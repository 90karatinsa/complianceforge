BEGIN;

CREATE TABLE IF NOT EXISTS policy_exceptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  component_purl TEXT,
  scope TEXT NOT NULL CHECK (scope IN ('package', 'project', 'organization')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'revoked', 'expired')),
  rationale TEXT,
  requested_by TEXT NOT NULL,
  approved_by TEXT,
  approval_notes TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  approved_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_exceptions_tenant_id ON policy_exceptions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_project_id ON policy_exceptions (project_id);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_component_purl ON policy_exceptions (component_purl);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_status ON policy_exceptions (status);
CREATE INDEX IF NOT EXISTS idx_policy_exceptions_expires_at ON policy_exceptions (expires_at);

COMMIT;
