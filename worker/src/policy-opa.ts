// SPDX-License-Identifier: MIT

import type { LicenseFinding, ScannerResult, VulnerabilityFinding } from './scanners.js';

import { assertNetworkFetchAllowed } from './network-guard.js';

export interface PolicyRules {
  readonly allowed_spdx?: string[];
  readonly denied_spdx?: string[];
  readonly cvss_threshold?: number;
  readonly allowlists?: {
    readonly licenses?: string[];
    readonly vulnerabilities?: string[];
  };
  readonly opa?: {
    readonly bundle_url?: string;
    readonly decisions?: OpaDecision[];
    readonly cache_ttl_seconds?: number;
  };
}

export interface OpaDecision {
  readonly match?: {
    readonly component_purl?: string;
    readonly spdx?: string;
    readonly cve?: string;
  };
  readonly effect?: 'allow' | 'deny';
  readonly reason?: string;
}

export interface PolicyEvaluationOptions {
  readonly rules: PolicyRules | null | undefined;
  readonly scannerResult: ScannerResult;
  readonly fetchImpl?: typeof fetch;
}

export interface PolicyEvaluationResult {
  readonly result: 'pass' | 'fail';
  readonly reasons: string[];
  readonly opaDecisions: string[];
}

interface BundleCacheEntry {
  readonly decisions: OpaDecision[];
  readonly expiresAt: number;
}

const opaBundleCache = new Map<string, BundleCacheEntry>();

export function __unsafeResetOpaBundleCache(): void {
  opaBundleCache.clear();
}

function normalizeHttpsUrl(rawUrl: string): string {
  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('OPA bundle_url must be a valid HTTPS URL.');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('OPA bundle_url must use HTTPS.');
  }

  parsed.username = '';
  parsed.password = '';
  return parsed.toString();
}

function normalizeSet(values: readonly string[] | undefined): Set<string> {
  return new Set((values ?? []).map((value) => value.toUpperCase()));
}

export function extractCvssScore(vulnerability: VulnerabilityFinding['vulnerabilities'][number]): number | undefined {
  if (!Array.isArray(vulnerability.severity)) {
    return undefined;
  }

  for (const entry of vulnerability.severity) {
    if (!entry) {
      continue;
    }

    const candidate =
      typeof (entry as { score?: unknown }).score === 'string'
        ? Number((entry as { score: string }).score)
        : typeof (entry as { score?: unknown }).score === 'number'
          ? Number((entry as { score: number }).score)
          : typeof (entry as { value?: unknown }).value === 'string'
            ? Number((entry as { value: string }).value)
            : typeof (entry as { value?: unknown }).value === 'number'
              ? Number((entry as { value: number }).value)
              : undefined;

    if (typeof candidate === 'number' && Number.isFinite(candidate)) {
      return candidate;
    }
  }

  return undefined;
}

function evaluateStaticRules(rules: PolicyRules | null | undefined, scannerResult: ScannerResult): string[] {
  if (!rules) {
    return [];
  }

  const reasons: string[] = [];

  const allowed = normalizeSet(rules.allowed_spdx);
  const denied = normalizeSet(rules.denied_spdx);
  const allowlistedLicenses = normalizeSet(rules.allowlists?.licenses);
  const allowlistedVulns = normalizeSet(rules.allowlists?.vulnerabilities);

  for (const license of scannerResult.licenses) {
    const spdx = license.spdxId?.toUpperCase();

    if (!spdx) {
      continue;
    }

    if (allowed.size > 0 && !allowed.has(spdx) && !allowlistedLicenses.has(spdx)) {
      reasons.push(`License ${spdx} is not allowed.`);
    }

    if (denied.has(spdx) && !allowlistedLicenses.has(spdx)) {
      reasons.push(`License ${spdx} is denied.`);
    }
  }

  if (typeof rules.cvss_threshold === 'number') {
    for (const finding of scannerResult.vulnerabilities) {
      for (const vulnerability of finding.vulnerabilities) {
        const id = vulnerability.id?.toUpperCase();
        const score = extractCvssScore(vulnerability);

        if (typeof score === 'number' && score >= rules.cvss_threshold) {
          if (!id || !allowlistedVulns.has(id)) {
            reasons.push(`Vulnerability ${id ?? 'unknown'} exceeds CVSS threshold ${rules.cvss_threshold}.`);
          }
        }
      }
    }
  }

  return reasons;
}

function matchesDecision(decision: OpaDecision, context: { purl?: string; spdx?: string; cve?: string }): boolean {
  if (!decision.match) {
    return false;
  }

  const normalizedMatchPurl = decision.match.component_purl?.toLowerCase();
  const normalizedMatchSpdx = decision.match.spdx?.toUpperCase();
  const normalizedMatchCve = decision.match.cve?.toUpperCase();

  if (normalizedMatchPurl && context.purl?.toLowerCase() === normalizedMatchPurl) {
    return true;
  }

  if (normalizedMatchSpdx && context.spdx?.toUpperCase() === normalizedMatchSpdx) {
    return true;
  }

  if (normalizedMatchCve && context.cve?.toUpperCase() === normalizedMatchCve) {
    return true;
  }

  return false;
}

async function loadBundleDecisions(
  rules: PolicyRules | null | undefined,
  fetchImpl: typeof fetch | undefined
): Promise<OpaDecision[]> {
  const configured = rules?.opa?.decisions ?? [];
  const decisions: OpaDecision[] = configured.filter((decision): decision is OpaDecision => !!decision);

  const configuredBundleUrl = rules?.opa?.bundle_url;

  if (!configuredBundleUrl) {
    return decisions;
  }

  const bundleUrl = normalizeHttpsUrl(configuredBundleUrl);
  const ttlSeconds = Math.max(rules?.opa?.cache_ttl_seconds ?? 60, 1);
  const ttlMs = ttlSeconds * 1000;
  const now = Date.now();

  const cached = opaBundleCache.get(bundleUrl);

  if (cached && cached.expiresAt > now) {
    return decisions.concat(cached.decisions.map((decision) => ({ ...decision })));
  }

  assertNetworkFetchAllowed('OPA bundle downloads');
  const impl = fetchImpl ?? fetch;
  const response = await impl(bundleUrl, { headers: { accept: 'application/json' } });

  if (!response.ok) {
    throw new Error(`OPA bundle request failed with status ${response.status}`);
  }

  const payload = (await response.json()) as { decisions?: unknown };
  const fetched: OpaDecision[] = [];

  if (Array.isArray(payload.decisions)) {
    for (const entry of payload.decisions) {
      if (entry && typeof entry === 'object') {
        const decision = entry as OpaDecision;
        decisions.push(decision);
        fetched.push({ ...decision });
      }
    }
  }

  opaBundleCache.set(bundleUrl, { decisions: fetched, expiresAt: now + ttlMs });

  return decisions;
}

export async function evaluatePolicy(
  options: PolicyEvaluationOptions
): Promise<PolicyEvaluationResult> {
  const reasons = evaluateStaticRules(options.rules, options.scannerResult);
  const opaDecisions: string[] = [];

  const decisions = await loadBundleDecisions(options.rules, options.fetchImpl);

  if (decisions.length > 0) {
    for (const decision of decisions) {
      if (!decision || decision.effect !== 'deny') {
        continue;
      }

      const reason = decision.reason ?? 'Denied by OPA policy.';

      for (const license of options.scannerResult.licenses) {
        if (matchesDecision(decision, { spdx: license.spdxId })) {
          reasons.push(reason);
          opaDecisions.push(reason);
          break;
        }
      }

      for (const finding of options.scannerResult.vulnerabilities) {
        const matched = finding.vulnerabilities.some((vulnerability) =>
          matchesDecision(decision, {
            purl: finding.package.purl,
            cve: vulnerability.id
          })
        );

        if (matched) {
          reasons.push(reason);
          opaDecisions.push(reason);
          break;
        }
      }
    }
  }

  return {
    result: reasons.length === 0 ? 'pass' : 'fail',
    reasons,
    opaDecisions
  };
}

