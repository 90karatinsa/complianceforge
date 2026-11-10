// SPDX-License-Identifier: MIT

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import process from 'node:process';
import { createHash } from 'node:crypto';

const DEFAULT_FILES = ['policy-evaluation.json', 'sbom.cyclonedx.json', 'findings-summary.json'] as const;

type StableJson = string | number | boolean | null | StableJson[] | { [key: string]: StableJson };

function canonicalize(value: unknown): StableJson {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .map(([key, entry]) => [key, canonicalize(entry)] as const)
      .sort(([a], [b]) => a.localeCompare(b));
    return entries.reduce<Record<string, StableJson>>((acc, [key, entry]) => {
      acc[key] = entry;
      return acc;
    }, {});
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return null;
    }
    return Number(value);
  }

  if (typeof value === 'string' || typeof value === 'boolean' || value === null) {
    return value;
  }

  return null;
}

function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

async function hashJsonFile(path: string): Promise<string> {
  const contents = await readFile(path, 'utf8');
  let normalized: string;
  try {
    const parsed = JSON.parse(contents) as unknown;
    normalized = stableStringify(parsed);
  } catch (error) {
    throw new Error(`Failed to parse JSON from ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }

  return createHash('sha256').update(normalized).digest('hex');
}

export interface ComparisonResult {
  readonly success: boolean;
  readonly mismatches: Array<{
    file: string;
    baselineHash: string | null;
    candidateHash: string | null;
  }>;
}

interface CompareOptions {
  readonly baselineDir: string;
  readonly candidateDir: string;
  readonly files?: readonly string[];
  readonly logger?: (message: string) => void;
}

export async function compareScanOutputs(options: CompareOptions): Promise<ComparisonResult> {
  const files = options.files ?? DEFAULT_FILES;
  const mismatches: ComparisonResult['mismatches'] = [];

  for (const file of files) {
    const baselinePath = join(options.baselineDir, file);
    const candidatePath = join(options.candidateDir, file);

    let baselineHash: string | null = null;
    let candidateHash: string | null = null;

    try {
      baselineHash = await hashJsonFile(baselinePath);
    } catch (error) {
      mismatches.push({ file, baselineHash: null, candidateHash: null });
      options.logger?.(`Baseline file ${file} could not be read: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }

    try {
      candidateHash = await hashJsonFile(candidatePath);
    } catch (error) {
      mismatches.push({ file, baselineHash, candidateHash: null });
      options.logger?.(`Candidate file ${file} could not be read: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }

    if (baselineHash !== candidateHash) {
      mismatches.push({ file, baselineHash, candidateHash });
      options.logger?.(`Mismatch detected for ${file}`);
    }
  }

  return { success: mismatches.length === 0, mismatches };
}

function printResult(result: ComparisonResult): void {
  if (result.success) {
    console.log('All tracked artifacts match between runs.');
    return;
  }

  console.error('Determinism check failed. Mismatched files:');
  for (const mismatch of result.mismatches) {
    console.error(
      ` - ${mismatch.file}: baseline=${mismatch.baselineHash ?? 'missing'}, candidate=${mismatch.candidateHash ?? 'missing'}`
    );
  }
}

function parseCliArgs(argv: readonly string[]): { baseline?: string; candidate?: string } {
  const [, , baseline, candidate] = argv;
  return { baseline, candidate };
}

async function runCli(argv: readonly string[]): Promise<number> {
  const { baseline, candidate } = parseCliArgs(argv);

  if (!baseline || !candidate) {
    console.error('Usage: determinism-check <baseline-dir> <candidate-dir>');
    return 1;
  }

  const result = await compareScanOutputs({ baselineDir: baseline, candidateDir: candidate, logger: console.log });
  printResult(result);
  return result.success ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runCli(process.argv)
    .then((code) => {
      if (code !== 0) {
        process.exit(code);
      }
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exit(1);
    });
}
