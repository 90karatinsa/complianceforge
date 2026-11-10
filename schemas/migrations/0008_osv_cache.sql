-- SPDX-License-Identifier: MIT

CREATE TABLE IF NOT EXISTS osv_cache (
  tenant_id UUID NOT NULL,
  package_purl TEXT NOT NULL,
  feed_version TEXT NOT NULL,
  vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, package_purl, feed_version)
);

CREATE INDEX IF NOT EXISTS idx_osv_cache_tenant_feed ON osv_cache (tenant_id, feed_version, fetched_at DESC);
