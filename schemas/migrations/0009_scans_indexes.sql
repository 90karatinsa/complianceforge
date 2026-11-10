-- SPDX-License-Identifier: MIT

-- These indexes keep /v1/scans pagination within the expected SLA by
-- aligning the ORDER BY on (created_at DESC, id DESC) with composite
-- keys filtered by tenant and project scope.
CREATE INDEX IF NOT EXISTS idx_scans_tenant_created_desc
  ON scans (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_scans_project_created_desc
  ON scans (project_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_scans_project_status_created_desc
  ON scans (project_id, status, created_at DESC, id DESC);
