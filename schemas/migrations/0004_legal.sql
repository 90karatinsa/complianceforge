BEGIN;

CREATE TABLE IF NOT EXISTS legal_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  license_id UUID REFERENCES licenses(id) ON DELETE SET NULL,
  vuln_id UUID REFERENCES vulns(id) ON DELETE SET NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  obligations JSONB NOT NULL DEFAULT '{}'::jsonb,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS legal_decisions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES legal_findings(id) ON DELETE CASCADE,
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'conditional')),
  rationale TEXT,
  decided_by TEXT,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS legal_signoffs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  decision_id UUID NOT NULL REFERENCES legal_decisions(id) ON DELETE CASCADE,
  signer_name TEXT NOT NULL,
  signer_email TEXT,
  signature_hash TEXT NOT NULL,
  signature_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_legal_findings_tenant_id ON legal_findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_legal_findings_scan_id ON legal_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_legal_findings_status ON legal_findings (status);
CREATE INDEX IF NOT EXISTS idx_legal_decisions_tenant_id ON legal_decisions (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_decisions_finding_latest ON legal_decisions (finding_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_legal_signoffs_tenant_id ON legal_signoffs (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_signoffs_decision_id ON legal_signoffs (decision_id);

COMMIT;
