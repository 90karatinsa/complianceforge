// SPDX-License-Identifier: MIT

import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runSecurityScan, SecurityScanError, __setExecFileImplementation } from '../../scripts/security-scan.ts';

type ExecResponse = {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly error?: Error & { stdout?: string; stderr?: string; code?: string };
};

function createExecStub(responses: ExecResponse[]) {
  return (file: string, args: readonly string[], options: unknown, callback: (error: Error | null, stdout: string, stderr: string) => void) => {
    const response = responses.shift() ?? { stdout: '', stderr: '' };
    if (response.error) {
      callback(response.error, response.stdout ?? '', response.stderr ?? '');
    } else {
      callback(null, response.stdout ?? '', response.stderr ?? '');
    }
  };
}

describe('runSecurityScan', () => {
  const responses: ExecResponse[] = [];

  beforeEach(() => {
    responses.length = 0;
    __setExecFileImplementation(createExecStub(responses));
  });

  afterEach(() => {
    __setExecFileImplementation();
    vi.restoreAllMocks();
  });

  function queueExecResponse(response: ExecResponse): void {
    responses.push(response);
  }

  it('passes when npm audit and gitleaks report no issues', async () => {
    queueExecResponse({ stdout: JSON.stringify({ vulnerabilities: {} }) });
    queueExecResponse({ stdout: '[]' });

    await expect(runSecurityScan({ logger: () => {} })).resolves.toBeUndefined();
    expect(responses).toHaveLength(0);
  });

  it('fails when npm audit reports high severity vulnerabilities', async () => {
    const error = Object.assign(new Error('audit failed'), {
      stdout: JSON.stringify({ vulnerabilities: { test: { severity: 'high', via: [{}] } } })
    });
    queueExecResponse({ error, stdout: error.stdout });

    await expect(runSecurityScan({ logger: () => {} })).rejects.toBeInstanceOf(SecurityScanError);
  });

  it('treats npm audit network failures as offline warnings', async () => {
    const logger = vi.fn();
    const networkError = Object.assign(new Error('getaddrinfo ENOTFOUND registry.npmjs.org'), {
      code: 'ENOTFOUND',
      stderr: 'getaddrinfo ENOTFOUND registry.npmjs.org'
    });
    queueExecResponse({ error: networkError });
    queueExecResponse({ stdout: '[]' });

    await expect(runSecurityScan({ logger })).resolves.toBeUndefined();
    expect(logger).toHaveBeenCalledWith(
      expect.stringContaining('npm audit unavailable (offline or missing binary)')
    );
  });

  it('falls back to built-in secret scanning and honors allowlist patterns', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'security-'));
    await mkdir(tempDir, { recursive: true });
    const allowlistedValue = ['API_KEY', 'demo-value'].join('=');
    await writeFile(path.join(tempDir, 'allowed.txt'), allowlistedValue, 'utf8');

    queueExecResponse({ stdout: JSON.stringify({ vulnerabilities: {} }) });
    const enoent = Object.assign(new Error('not found'), { code: 'ENOENT' });
    queueExecResponse({ error: enoent });

    await expect(
      runSecurityScan({ cwd: tempDir, allowlist: [/[A-Za-z]+\.txt/], logger: () => {} })
    ).resolves.toBeUndefined();
  });

  it('fails when secret findings remain after allowlist filtering', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'security-'));
    await mkdir(tempDir, { recursive: true });
    const rawSecret = ['token', '123456789ABC'].join('=');
    await writeFile(path.join(tempDir, 'secret.txt'), rawSecret, 'utf8');

    queueExecResponse({ stdout: JSON.stringify({ vulnerabilities: {} }) });
    const enoent = Object.assign(new Error('not found'), { code: 'ENOENT' });
    queueExecResponse({ error: enoent });

    await expect(
      runSecurityScan({ cwd: tempDir, logger: () => {} })
    ).rejects.toBeInstanceOf(SecurityScanError);
  });

  it('fails when gitleaks returns findings', async () => {
    queueExecResponse({ stdout: JSON.stringify({ vulnerabilities: {} }) });
    const findings = JSON.stringify([{ file: 'src/index.ts', line: 10, lineText: 'API_KEY=secret' }]);
    const error = Object.assign(new Error('findings'), { stdout: findings });
    queueExecResponse({ error, stdout: findings });

    await expect(runSecurityScan({ logger: () => {} })).rejects.toBeInstanceOf(SecurityScanError);
  });

  it('allowlists the demo API token by default', async () => {
    queueExecResponse({ stdout: JSON.stringify({ vulnerabilities: {} }) });
    const findings = JSON.stringify([
      {
        file: 'README.md',
        line: 44,
        lineText: 'Authorization: Bearer alterra-demo-api-token'
      }
    ]);
    const error = Object.assign(new Error('findings'), { stdout: findings });
    queueExecResponse({ error, stdout: findings });

    await expect(runSecurityScan({ logger: () => {} })).resolves.toBeUndefined();
  });
});
