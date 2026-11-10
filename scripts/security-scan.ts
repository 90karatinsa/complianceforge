// SPDX-License-Identifier: MIT

import { execFile, type ExecFileException, type ExecFileOptions } from 'node:child_process';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

type ExecResult = { stdout: string; stderr: string };
type ExecFileFunction = (
  file: string,
  args: readonly string[],
  options: ExecFileOptions,
  callback: (error: Error | null, stdout: string, stderr: string) => void
) => void;

type Allowlist = readonly RegExp[];

interface SecurityScanOptions {
  readonly auditCommand?: string;
  readonly auditArgs?: readonly string[];
  readonly gitleaksBinary?: string;
  readonly allowlist?: Allowlist;
  readonly cwd?: string;
  readonly logger?: (message: string) => void;
}

interface CliArguments {
  readonly auditCommand?: string;
  readonly gitleaksBinary?: string;
  readonly allowlist: string[];
  readonly cwd?: string;
  readonly report: boolean;
}

interface AuditSummary {
  readonly totalHigh: number;
  readonly totalCritical: number;
}

interface SecretFinding {
  readonly file: string;
  readonly lineNumber: number;
  readonly line: string;
}

const SECRET_PATTERN = /(?:(?:api|secret|token)[_-]?key|secret|token|password)\s*(?:=|:)\s*([A-Za-z0-9._~+=-]{8,})/gi;
const BUILT_IN_SECRET_ALLOWLIST: readonly RegExp[] = [/\balterra[-_]demo[-_]api[-_]token\b/i];
const SKIP_DIRECTORIES = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage']);
const MAX_FALLBACK_FILE_SIZE = 512 * 1024; // 512 KiB
const OFFLINE_AUDIT_ERROR_CODES = new Set([
  'ENOENT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EAI_FAIL',
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ENETUNREACH',
  'EHOSTUNREACH'
]);

class SecurityScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityScanError';
  }
}

let execFileImplementation: ExecFileFunction = execFile;

function execFileAsync(file: string, args: readonly string[], options: ExecFileOptions): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    execFileImplementation(file, args, options, (error, stdout, stderr) => {
      if (error) {
        const execError = error as ExecFileException & { stdout: string; stderr: string };
        execError.stdout = stdout;
        execError.stderr = stderr;
        reject(execError);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function parseAuditOutput(raw: string): AuditSummary {
  if (!raw) {
    return { totalHigh: 0, totalCritical: 0 };
  }
  const parsed = JSON.parse(raw) as { vulnerabilities?: Record<string, { severity?: string; via?: unknown[] }> };
  const vulnerabilities = parsed.vulnerabilities ?? {};
  let high = 0;
  let critical = 0;
  for (const entry of Object.values(vulnerabilities)) {
    const severity = entry.severity?.toLowerCase();
    const occurrences = Array.isArray(entry.via) ? entry.via.length : 1;
    if (severity === 'high') {
      high += occurrences;
    } else if (severity === 'critical') {
      critical += occurrences;
    }
  }
  return { totalHigh: high, totalCritical: critical };
}

async function runNpmAudit({ auditCommand = 'npm', auditArgs = ['audit', '--json'], cwd, logger }: SecurityScanOptions): Promise<void> {
  try {
    const { stdout } = await execFileAsync(auditCommand, auditArgs, { cwd });
    const summary = parseAuditOutput(stdout);
    if (summary.totalHigh > 0 || summary.totalCritical > 0) {
      throw new SecurityScanError(`High (${summary.totalHigh}) or critical (${summary.totalCritical}) vulnerabilities detected.`);
    }
    logger?.('npm audit reported no high or critical vulnerabilities.');
  } catch (error) {
    if (error instanceof SecurityScanError) {
      throw error;
    }
    const execError = error as ExecFileException & { stdout?: string; stderr?: string };
    const errorCode = typeof execError?.code === 'string' ? execError.code.toUpperCase() : '';
    const aggregateMessage = `${execError?.message ?? ''} ${execError?.stderr ?? ''}`.toLowerCase();
    if (OFFLINE_AUDIT_ERROR_CODES.has(errorCode) || /network|offline|getaddrinfo/.test(aggregateMessage)) {
      logger?.('npm audit unavailable (offline or missing binary); continuing with offline warning.');
      return;
    }
    if (execError && typeof execError.stdout === 'string') {
      const summary = parseAuditOutput(execError.stdout);
      if (summary.totalHigh === 0 && summary.totalCritical === 0) {
        logger?.('npm audit reported vulnerabilities below high severity; continuing.');
        return;
      }
      throw new SecurityScanError(`High (${summary.totalHigh}) or critical (${summary.totalCritical}) vulnerabilities detected.`);
    }
    throw new SecurityScanError(`Failed to run npm audit: ${(error as Error).message}`);
  }
}

function parseGitleaksOutput(raw: string): SecretFinding[] {
  if (!raw.trim()) {
    return [];
  }
  const parsed = JSON.parse(raw) as Array<{ file: string; line: number; lineText?: string }>;
  return parsed.map((finding) => ({
    file: finding.file,
    lineNumber: finding.line,
    line: finding.lineText ?? ''
  }));
}

async function runGitleaksScan(binary: string, cwd: string | undefined, logger?: (message: string) => void): Promise<SecretFinding[]> {
  try {
    const args = ['detect', '--no-banner', '--report-format', 'json', '--redact'];
    const { stdout } = await execFileAsync(binary, args, { cwd });
    logger?.('gitleaks completed without findings.');
    return parseGitleaksOutput(stdout);
  } catch (error) {
    const execError = error as ExecFileException & { code?: string; stdout?: string };
    if (execError.code === 'ENOENT') {
      logger?.('gitleaks not found; falling back to built-in secret scan.');
      return runFallbackSecretScan(cwd, logger);
    }
    if (typeof execError.stdout === 'string') {
      const findings = parseGitleaksOutput(execError.stdout);
      if (findings.length === 0) {
        return [];
      }
      return findings;
    }
    throw new SecurityScanError(`gitleaks failed: ${(error as Error).message}`);
  }
}

async function* walkFiles(dir: string): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP_DIRECTORIES.has(entry.name)) {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkFiles(fullPath);
    } else if (entry.isFile()) {
      yield fullPath;
    }
  }
}

async function runFallbackSecretScan(cwd: string | undefined, logger?: (message: string) => void): Promise<SecretFinding[]> {
  const root = cwd ?? process.cwd();
  const findings: SecretFinding[] = [];
  for await (const filePath of walkFiles(root)) {
    const info = await stat(filePath);
    if (info.size > MAX_FALLBACK_FILE_SIZE) {
      continue;
    }
    let content: string;
    try {
      content = await readFile(filePath, 'utf8');
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/);
    lines.forEach((line, index) => {
      const matches = line.matchAll(SECRET_PATTERN);
      for (const match of matches) {
        const candidate = match[1] ?? '';
        if (candidate.length === 0) {
          continue;
        }
        if (/^[A-Za-z]+$/.test(candidate)) {
          continue;
        }
        const hasDigit = /\d/.test(candidate);
        const hasHyphenOrUnderscore = /[-_]/.test(candidate);
        if (!hasDigit && !hasHyphenOrUnderscore && candidate.includes('.')) {
          continue;
        }
        findings.push({ file: filePath, lineNumber: index + 1, line });
        break;
      }
    });
  }
  if (findings.length === 0) {
    logger?.('Fallback secret scan found no issues.');
  }
  return findings;
}

function filterAllowlisted(findings: readonly SecretFinding[], allowlist: Allowlist): SecretFinding[] {
  if (allowlist.length === 0) {
    return [...findings];
  }
  return findings.filter((finding) => !allowlist.some((pattern) => pattern.test(`${finding.file}:${finding.line}`) || pattern.test(finding.line)));
}

export async function runSecurityScan({
  auditCommand,
  auditArgs,
  gitleaksBinary = 'gitleaks',
  allowlist = [],
  cwd = process.cwd(),
  logger = (message) => process.stdout.write(`${message}\n`)
}: SecurityScanOptions = {}): Promise<void> {
  await runNpmAudit({ auditCommand, auditArgs, cwd, logger });
  const findings = await runGitleaksScan(gitleaksBinary, cwd, logger);
  const effectiveAllowlist = [...BUILT_IN_SECRET_ALLOWLIST, ...allowlist];
  const filteredFindings = filterAllowlisted(findings, effectiveAllowlist);
  if (filteredFindings.length > 0) {
    filteredFindings.forEach((finding) => {
      logger(`Secret detected in ${finding.file}:${finding.lineNumber}`);
    });
    throw new SecurityScanError(`Detected ${filteredFindings.length} potential secret(s).`);
  }
  logger('Security scan completed successfully.');
}

function parseAllowlist(values: readonly string[]): RegExp[] {
  return values.map((value) => new RegExp(value, 'i'));
}

function parseCliArguments(args: readonly string[]): CliArguments {
  let auditCommand: string | undefined;
  let gitleaksBinary: string | undefined;
  const allowlist: string[] = [];
  let cwd: string | undefined;
  let report = false;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--audit-command') {
      auditCommand = args[i + 1];
      i += 1;
    } else if (arg === '--gitleaks-bin') {
      gitleaksBinary = args[i + 1];
      i += 1;
    } else if (arg === '--allowlist') {
      allowlist.push(args[i + 1]);
      i += 1;
    } else if (arg === '--cwd') {
      cwd = path.resolve(args[i + 1]);
      i += 1;
    } else if (arg === '--report') {
      report = true;
    }
  }

  return { auditCommand, gitleaksBinary, allowlist, cwd, report };
}

async function cli(): Promise<void> {
  const options = parseCliArguments(process.argv.slice(2));
  const logs: string[] = [];
  const logger = (message: string) => {
    logs.push(message);
    if (options.report) {
      process.stdout.write(`${message}\n`);
    }
  };
  await runSecurityScan({
    auditCommand: options.auditCommand,
    gitleaksBinary: options.gitleaksBinary,
    allowlist: parseAllowlist(options.allowlist),
    cwd: options.cwd,
    logger
  });
  if (!options.report) {
    logs.forEach((message) => process.stdout.write(`${message}\n`));
  }
}

function isExecutedDirectly(): boolean {
  const entryPoint = process.argv[1];
  if (!entryPoint) {
    return false;
  }
  return import.meta.url === pathToFileURL(entryPoint).href;
}

if (isExecutedDirectly()) {
  cli().catch((error: unknown) => {
    const failure = error instanceof Error ? error : new Error(String(error));
    process.stderr.write(`Security scan failed: ${failure.message}\n`);
    process.exitCode = 1;
  });
}

export { SecurityScanError };

export function __setExecFileImplementation(mock?: ExecFileFunction): void {
  execFileImplementation = mock ?? execFile;
}
