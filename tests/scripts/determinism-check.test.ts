// SPDX-License-Identifier: MIT

import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compareScanOutputs } from '../../scripts/determinism-check.ts';

async function createFixtureDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), `determinism-${prefix}-`));
}

async function writeArtifacts(dir: string, modifier?: (file: string, data: unknown) => unknown): Promise<void> {
  const baseData = {
    policy: { result: 'pass', reasons: ['threshold'] },
    sbom: { metadata: { components: 10 } },
    findings: { vulnerabilities: [] }
  } as const;

  const mappings: Array<[string, unknown]> = [
    ['policy-evaluation.json', baseData.policy],
    ['sbom.cyclonedx.json', baseData.sbom],
    ['findings-summary.json', baseData.findings]
  ];

  for (const [file, data] of mappings) {
    const final = modifier ? modifier(file, structuredClone(data)) : data;
    await writeFile(join(dir, file), JSON.stringify(final, null, 2));
  }
}

describe('determinism check script', () => {
  const createdDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(createdDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('reports success when baseline and candidate hashes match', async () => {
    const baseline = await createFixtureDir('baseline');
    const candidate = await createFixtureDir('candidate');
    createdDirs.push(baseline, candidate);

    await writeArtifacts(baseline);
    await writeArtifacts(candidate);

    const result = await compareScanOutputs({ baselineDir: baseline, candidateDir: candidate });

    expect(result.success).toBe(true);
    expect(result.mismatches).toEqual([]);
  });

  it('detects mismatches when artifacts differ', async () => {
    const baseline = await createFixtureDir('baseline');
    const candidate = await createFixtureDir('candidate');
    createdDirs.push(baseline, candidate);

    await writeArtifacts(baseline);
    await writeArtifacts(candidate, (file, data) => {
      if (file === 'policy-evaluation.json' && typeof data === 'object' && data && 'result' in data) {
        (data as { result: string }).result = 'fail';
      }
      return data;
    });

    const result = await compareScanOutputs({ baselineDir: baseline, candidateDir: candidate });

    expect(result.success).toBe(false);
    expect(result.mismatches).toEqual([
      expect.objectContaining({ file: 'policy-evaluation.json', baselineHash: expect.any(String), candidateHash: expect.any(String) })
    ]);
  });
});
