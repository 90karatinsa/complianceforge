-- SPDX-License-Identifier: MIT
-- Adds composite indexes to accelerate audit event listings and exports.

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created_desc
  ON audit_log_events (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_type_created_desc
  ON audit_log_events (tenant_id, event_type, created_at DESC, id DESC);
