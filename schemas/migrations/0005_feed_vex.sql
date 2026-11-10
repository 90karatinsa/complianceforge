BEGIN;

CREATE TABLE IF NOT EXISTS feed_manifests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  verified_at TIMESTAMPTZ,
  signature TEXT,
  UNIQUE (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS feed_packages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  manifest_id UUID NOT NULL REFERENCES feed_manifests(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (char_length(sha256) = 64),
  size_bytes BIGINT CHECK (size_bytes IS NULL OR size_bytes >= 0),
  stored_at TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, filename, sha256)
);

CREATE TABLE IF NOT EXISTS vex_statements (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  component_purl TEXT NOT NULL,
  advisory_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation', 'unknown')),
  justification TEXT,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_feed_manifests_tenant_id ON feed_manifests (tenant_id);
CREATE INDEX IF NOT EXISTS idx_feed_packages_manifest_id ON feed_packages (manifest_id);
CREATE INDEX IF NOT EXISTS idx_vex_statements_tenant_id ON vex_statements (tenant_id);
CREATE INDEX IF NOT EXISTS idx_vex_statements_component_purl ON vex_statements (component_purl);
CREATE INDEX IF NOT EXISTS idx_vex_statements_status ON vex_statements (status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_statements_component_advisory ON vex_statements (tenant_id, component_purl, advisory_id) WHERE advisory_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_statements_component_without_advisory ON vex_statements (tenant_id, component_purl) WHERE advisory_id IS NULL;

COMMIT;
