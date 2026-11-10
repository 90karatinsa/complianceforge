BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (slug)
);

CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name),
  UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  repo_url TEXT,
  oci_ref TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  rules JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS artifacts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  ref JSONB NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  artifact_id UUID REFERENCES artifacts(id) ON DELETE SET NULL,
  policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
  policy_result TEXT CHECK (policy_result IN ('pass', 'warn', 'fail')),
  status TEXT NOT NULL,
  findings JSONB NOT NULL DEFAULT '{}'::jsonb,
  duration_ms NUMERIC,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sboms (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  artifact_id UUID REFERENCES artifacts(id) ON DELETE SET NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  format TEXT NOT NULL,
  bom JSONB NOT NULL,
  component_count INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS licenses (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  component_purl TEXT NOT NULL,
  detected_spdx_id TEXT,
  evidence JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulns (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  component_purl TEXT NOT NULL,
  source TEXT NOT NULL,
  cve_id TEXT,
  severity TEXT,
  cvss NUMERIC,
  summary TEXT,
  fixed_version TEXT,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhooks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT,
  events TEXT[] NOT NULL DEFAULT '{}'::text[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS usage_metrics (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  period_start TIMESTAMPTZ NOT NULL,
  period_end TIMESTAMPTZ NOT NULL,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, period_start)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects (tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_repo_url ON projects (repo_url);
CREATE INDEX IF NOT EXISTS idx_projects_oci_ref ON projects (oci_ref);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_id ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_project_id ON artifacts (project_id);
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans (project_id);
CREATE INDEX IF NOT EXISTS idx_scans_artifact_id ON scans (artifact_id);
CREATE INDEX IF NOT EXISTS idx_scans_policy_id ON scans (policy_id);
CREATE INDEX IF NOT EXISTS idx_scans_policy_result ON scans (policy_result);
CREATE INDEX IF NOT EXISTS idx_sboms_project_id ON sboms (project_id);
CREATE INDEX IF NOT EXISTS idx_sboms_scan_id ON sboms (scan_id);
CREATE INDEX IF NOT EXISTS idx_licenses_sbom_id ON licenses (sbom_id);
CREATE INDEX IF NOT EXISTS idx_licenses_component_purl ON licenses (component_purl);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulns (scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_component_purl ON vulns (component_purl);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns (severity);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_id ON webhooks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_metrics_tenant_id ON usage_metrics (tenant_id);

COMMIT;
