// SPDX-License-Identifier: MIT

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const readMigration = (fileName: string) =>
  readFileSync(resolve(__dirname, `../schemas/migrations/${fileName}`), 'utf-8');

const migrationSql = readMigration('0001_init.sql');

const auditMigrationSql = readMigration('0003_audit_evidence.sql');
const legalMigrationSql = readMigration('0004_legal.sql');
const feedMigrationSql = readMigration('0005_feed_vex.sql');
const exceptionsMigrationSql = readMigration('0006_exceptions.sql');
const noticeMigrationSql = readMigration('0007_notice_versions.sql');
const osvCacheMigrationSql = readMigration('0008_osv_cache.sql');
const scanIndexesMigrationSql = readMigration('0009_scans_indexes.sql');
const apiKeyArgonMigrationSql = readMigration('0010_api_key_argon2.sql');
const auditIndexesMigrationSql = readMigration('0011_audit_indexes.sql');
const webhookEncryptionMigrationSql = readMigration('0012_webhook_secret_encryption.sql');

describe('schema migration', () => {
  it('defines all required tables', () => {
    const expectedTables = [
      'CREATE TABLE IF NOT EXISTS tenants',
      'CREATE TABLE IF NOT EXISTS api_keys',
      'CREATE TABLE IF NOT EXISTS projects',
      'CREATE TABLE IF NOT EXISTS artifacts',
      'CREATE TABLE IF NOT EXISTS scans',
      'CREATE TABLE IF NOT EXISTS sboms',
      'CREATE TABLE IF NOT EXISTS licenses',
      'CREATE TABLE IF NOT EXISTS vulns',
      'CREATE TABLE IF NOT EXISTS policies',
      'CREATE TABLE IF NOT EXISTS webhooks',
      'CREATE TABLE IF NOT EXISTS usage_metrics'
    ];

    for (const token of expectedTables) {
      expect(migrationSql).toContain(token);
    }
  });

  it('includes the necessary columns and constraints', () => {
    const expectedTokens = [
      "policy_result TEXT CHECK (policy_result IN ('pass', 'warn', 'fail'))",
      'duration_ms NUMERIC',
      'format TEXT NOT NULL',
      'bom JSONB NOT NULL',
      'component_count INTEGER NOT NULL',
      'component_purl TEXT NOT NULL',
      'detected_spdx_id TEXT',
      'evidence JSONB NOT NULL',
      'source TEXT NOT NULL',
      'cve_id TEXT',
      'cvss NUMERIC',
      'summary TEXT',
      'fixed_version TEXT'
    ];

    for (const token of expectedTokens) {
      expect(migrationSql).toContain(token);
    }
  });

  it('creates the expected indexes', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_projects_repo_url ON projects (repo_url);',
      'CREATE INDEX IF NOT EXISTS idx_projects_oci_ref ON projects (oci_ref);',
      'CREATE INDEX IF NOT EXISTS idx_artifacts_project_id ON artifacts (project_id);',
      'CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans (project_id);',
      'CREATE INDEX IF NOT EXISTS idx_scans_artifact_id ON scans (artifact_id);',
      'CREATE INDEX IF NOT EXISTS idx_scans_policy_id ON scans (policy_id);',
      'CREATE INDEX IF NOT EXISTS idx_scans_policy_result ON scans (policy_result);',
      'CREATE INDEX IF NOT EXISTS idx_sboms_project_id ON sboms (project_id);',
      'CREATE INDEX IF NOT EXISTS idx_sboms_scan_id ON sboms (scan_id);',
      'CREATE INDEX IF NOT EXISTS idx_licenses_sbom_id ON licenses (sbom_id);',
      'CREATE INDEX IF NOT EXISTS idx_licenses_component_purl ON licenses (component_purl);',
      'CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulns (scan_id);',
      'CREATE INDEX IF NOT EXISTS idx_vulns_component_purl ON vulns (component_purl);',
      'CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns (severity);',
      'CREATE INDEX IF NOT EXISTS idx_policies_tenant_id ON policies (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_id ON webhooks (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_usage_metrics_tenant_id ON usage_metrics (tenant_id);'
    ];

    for (const token of expectedIndexes) {
      expect(migrationSql).toContain(token);
    }
  });
});

describe('audit and evidence migration', () => {
  it('defines audit and evidence tables with hashing metadata', () => {
    const expectedTokens = [
      'CREATE TABLE IF NOT EXISTS audit_log_events',
      'actor_type TEXT NOT NULL',
      "event_payload JSONB NOT NULL DEFAULT '{}'::jsonb",
      'event_hash TEXT NOT NULL',
      'CREATE TABLE IF NOT EXISTS evidence_packs',
      "manifest JSONB NOT NULL DEFAULT '{}'::jsonb",
      'signature TEXT'
    ];

    for (const token of expectedTokens) {
      expect(auditMigrationSql).toContain(token);
    }
  });

  it('declares the required indexes for audit evidence tracking', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_audit_log_events_tenant_id ON audit_log_events (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_audit_log_events_created_at ON audit_log_events (created_at);',
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_packs_scan_unique ON evidence_packs (tenant_id, scan_id) WHERE scan_id IS NOT NULL;'
    ];

    for (const token of expectedIndexes) {
      expect(auditMigrationSql).toContain(token);
    }
  });
});

describe('legal workflow migration', () => {
  it('creates legal findings, decisions, and signoff tables', () => {
    const expectedTables = [
      'CREATE TABLE IF NOT EXISTS legal_findings',
      "status TEXT NOT NULL DEFAULT 'pending'",
      'CREATE TABLE IF NOT EXISTS legal_decisions',
      "decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'conditional'))",
      'CREATE TABLE IF NOT EXISTS legal_signoffs',
      'signature_hash TEXT NOT NULL'
    ];

    for (const token of expectedTables) {
      expect(legalMigrationSql).toContain(token);
    }
  });

  it('enforces indexes for legal workflow tables', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_legal_findings_tenant_id ON legal_findings (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_legal_findings_status ON legal_findings (status);',
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_signoffs_decision_id ON legal_signoffs (decision_id);'
    ];

    for (const token of expectedIndexes) {
      expect(legalMigrationSql).toContain(token);
    }
  });
});

describe('feed and vex migration', () => {
  it('defines feed manifest and package storage tables', () => {
    const expectedTokens = [
      'CREATE TABLE IF NOT EXISTS feed_manifests',
      'version TEXT NOT NULL',
      "manifest JSONB NOT NULL DEFAULT '{}'::jsonb",
      'CREATE TABLE IF NOT EXISTS feed_packages',
      'filename TEXT NOT NULL',
      'sha256 TEXT NOT NULL'
    ];

    for (const token of expectedTokens) {
      expect(feedMigrationSql).toContain(token);
    }
  });

  it('captures VEX statement metadata and tenant scoped uniqueness', () => {
    const expectedTokens = [
      'CREATE TABLE IF NOT EXISTS vex_statements',
      "status TEXT NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation', 'unknown'))",
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_statements_component_advisory ON vex_statements (tenant_id, component_purl, advisory_id) WHERE advisory_id IS NOT NULL;',
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_statements_component_without_advisory ON vex_statements (tenant_id, component_purl) WHERE advisory_id IS NULL;'
    ];

    for (const token of expectedTokens) {
      expect(feedMigrationSql).toContain(token);
    }
  });
});

describe('scan index migration', () => {
  it('creates composite indexes matching scan listing queries', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_scans_tenant_created_desc\n  ON scans (tenant_id, created_at DESC, id DESC);',
      'CREATE INDEX IF NOT EXISTS idx_scans_project_created_desc\n  ON scans (project_id, created_at DESC, id DESC);',
      'CREATE INDEX IF NOT EXISTS idx_scans_project_status_created_desc\n  ON scans (project_id, status, created_at DESC, id DESC);'
    ];

    for (const token of expectedIndexes) {
      expect(scanIndexesMigrationSql).toContain(token);
    }
  });
});

describe('audit index migration', () => {
  it('adds composite indexes for audit listings and filters', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created_desc\n  ON audit_log_events (tenant_id, created_at DESC, id DESC);',
      'CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_type_created_desc\n  ON audit_log_events (tenant_id, event_type, created_at DESC, id DESC);'
    ];

    for (const token of expectedIndexes) {
      expect(auditIndexesMigrationSql).toContain(token);
    }
  });
});

describe('API key hashing migration', () => {
  it('adds lookup hash support and drops the legacy constraint', () => {
    expect(apiKeyArgonMigrationSql).toContain('ADD COLUMN IF NOT EXISTS token_lookup_hash TEXT;');
    expect(apiKeyArgonMigrationSql).toContain('CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_lookup_hash');
    expect(apiKeyArgonMigrationSql).toContain('DROP CONSTRAINT IF EXISTS api_keys_token_hash_key;');
  });
});

describe('webhook secret encryption migration', () => {
  it('introduces encryption storage columns and clears plaintext values', () => {
    expect(webhookEncryptionMigrationSql).toContain('ADD COLUMN IF NOT EXISTS secret_ciphertext BYTEA');
    expect(webhookEncryptionMigrationSql).toContain('ADD COLUMN IF NOT EXISTS secret_iv BYTEA');
    expect(webhookEncryptionMigrationSql).toContain('ADD COLUMN IF NOT EXISTS secret_auth_tag BYTEA');
    expect(webhookEncryptionMigrationSql).toContain('ADD COLUMN IF NOT EXISTS secret_last_four TEXT');
    expect(webhookEncryptionMigrationSql).toContain('SET secret = NULL');
  });
});

describe('policy exception migration', () => {
  it('creates policy exception storage with lifecycle metadata', () => {
    const expectedTokens = [
      'CREATE TABLE IF NOT EXISTS policy_exceptions',
      "scope TEXT NOT NULL CHECK (scope IN ('package', 'project', 'organization'))",
      "status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'revoked', 'expired'))",
      'requested_by TEXT NOT NULL',
      "metadata JSONB NOT NULL DEFAULT '{}'::jsonb"
    ];

    for (const token of expectedTokens) {
      expect(exceptionsMigrationSql).toContain(token);
    }
  });

  it('adds indexes for tenant lookups and expiry enforcement', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_policy_exceptions_tenant_id ON policy_exceptions (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_policy_exceptions_status ON policy_exceptions (status);',
      'CREATE INDEX IF NOT EXISTS idx_policy_exceptions_expires_at ON policy_exceptions (expires_at);'
    ];

    for (const token of expectedIndexes) {
      expect(exceptionsMigrationSql).toContain(token);
    }
  });
});

describe('osv cache migration', () => {
  it('stores vulnerability cache entries with feed scoping', () => {
    expect(osvCacheMigrationSql).toContain('CREATE TABLE IF NOT EXISTS osv_cache');
    expect(osvCacheMigrationSql).toContain('feed_version TEXT NOT NULL');
    expect(osvCacheMigrationSql).toContain("vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb");
    expect(osvCacheMigrationSql).toContain('PRIMARY KEY (tenant_id, package_purl, feed_version)');
  });

  it('adds indexes for cache lookup efficiency', () => {
    expect(osvCacheMigrationSql).toContain(
      'CREATE INDEX IF NOT EXISTS idx_osv_cache_tenant_feed ON osv_cache (tenant_id, feed_version, fetched_at DESC);'
    );
  });
});

describe('notice version migration', () => {
  it('persists finalized notice metadata with signature and feed linkage', () => {
    const expectedTokens = [
      'CREATE TABLE IF NOT EXISTS notice_versions',
      'signature_hash TEXT NOT NULL',
      "signoff_payload JSONB NOT NULL DEFAULT '{}'::jsonb",
      'feed_version TEXT'
    ];

    for (const token of expectedTokens) {
      expect(noticeMigrationSql).toContain(token);
    }
  });

  it('adds indexes for tenant, project, and scan retrieval', () => {
    const expectedIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_notice_versions_tenant_id ON notice_versions (tenant_id);',
      'CREATE INDEX IF NOT EXISTS idx_notice_versions_project_id ON notice_versions (project_id);',
      'CREATE INDEX IF NOT EXISTS idx_notice_versions_scan_id ON notice_versions (scan_id);',
      'CREATE INDEX IF NOT EXISTS idx_notice_versions_created_at ON notice_versions (created_at DESC);'
    ];

    for (const token of expectedIndexes) {
      expect(noticeMigrationSql).toContain(token);
    }
  });
});
