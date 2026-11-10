// SPDX-License-Identifier: MIT

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  cpSync,
  statSync,
  chmodSync
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

interface CommandPlan {
  readonly command: string;
  readonly args: string[];
}

interface DebBuildPlan {
  readonly dpkg: CommandPlan;
  readonly stagingDir: string;
  readonly outputPath: string;
  readonly checksumPath: string;
}

interface BuildOptions {
  readonly version?: string;
  readonly dpkgDebPath?: string;
  readonly runner?: (descriptor: CommandPlan) => void;
  readonly distDir?: string;
}

function resolveRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function loadPackageVersion(rootDir: string): string {
  const pkg = JSON.parse(readFileSync(path.join(rootDir, 'package.json'), 'utf8')) as { version?: string };
  if (!pkg.version) {
    throw new Error('package.json must define a version field.');
  }
  return pkg.version;
}

function hydrateControlTemplate(templatePath: string, version: string): string {
  return readFileSync(templatePath, 'utf8').replace(/@VERSION@/gu, version);
}

export function planDebBuild(options: BuildOptions = {}): DebBuildPlan {
  const rootDir = resolveRoot();
  const version = options.version ?? loadPackageVersion(rootDir);
  const distDir = options.distDir ?? path.join(rootDir, 'dist', 'installers', 'deb');
  const stagingDir = path.join(distDir, `atlas-sca_${version}`);
  const outputPath = path.join(distDir, `atlas-sca_${version}_amd64.deb`);
  const dpkgDebPath = options.dpkgDebPath ?? process.env.DPKG_DEB_PATH ?? 'dpkg-deb';
  const dpkgArgs = ['--build', '--root-owner-group', stagingDir, outputPath];
  return {
    dpkg: { command: dpkgDebPath, args: dpkgArgs },
    stagingDir,
    outputPath,
    checksumPath: `${outputPath}.sha256`
  };
}

function spawnRunner(plan: CommandPlan): void {
  const result = spawnSync(plan.command, plan.args, { stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(`Command failed: ${plan.command} ${plan.args.join(' ')}`);
  }
}

function populateStaging(stagingDir: string, version: string, rootDir: string): void {
  const templateRoot = path.join(rootDir, 'deploy', 'installers', 'deb');
  const payloadSource = path.join(templateRoot, 'payload');
  const debianSource = path.join(templateRoot, 'DEBIAN');
  cpSync(payloadSource, stagingDir, { recursive: true });
  const debianTarget = path.join(stagingDir, 'DEBIAN');
  mkdirSync(debianTarget, { recursive: true });
  const controlContent = hydrateControlTemplate(path.join(debianSource, 'control'), version);
  writeFileSync(path.join(debianTarget, 'control'), controlContent, 'utf8');
  for (const scriptName of ['preinst', 'postinst']) {
    const sourcePath = path.join(debianSource, scriptName);
    const targetPath = path.join(debianTarget, scriptName);
    const buffer = readFileSync(sourcePath);
    writeFileSync(targetPath, buffer);
    const stats = statSync(sourcePath);
    chmodSync(targetPath, stats.mode);
  }
}

export async function buildDebInstaller(options: BuildOptions = {}): Promise<string> {
  const rootDir = resolveRoot();
  const plan = planDebBuild(options);
  mkdirSync(path.dirname(plan.outputPath), { recursive: true });
  rmSync(plan.outputPath, { force: true });
  rmSync(plan.checksumPath, { force: true });
  rmSync(plan.stagingDir, { force: true, recursive: true });
  mkdirSync(plan.stagingDir, { recursive: true });
  const version = options.version ?? loadPackageVersion(rootDir);
  populateStaging(plan.stagingDir, version, rootDir);
  const originalEpoch = process.env.SOURCE_DATE_EPOCH;
  if (originalEpoch === undefined) {
    process.env.SOURCE_DATE_EPOCH = '1704067200';
  }

  try {
    const runner = options.runner ?? spawnRunner;
    runner(plan.dpkg);
    const hash = createHash('sha256');
    hash.update(readFileSync(plan.outputPath));
    const digest = hash.digest('hex');
    const checksumBody = `${digest}  ${path.basename(plan.outputPath)}\n`;
    writeFileSync(plan.checksumPath, checksumBody, 'utf8');
    return plan.outputPath;
  } finally {
    if (originalEpoch === undefined) {
      delete process.env.SOURCE_DATE_EPOCH;
    } else {
      process.env.SOURCE_DATE_EPOCH = originalEpoch;
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildDebInstaller().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
