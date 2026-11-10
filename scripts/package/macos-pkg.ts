// SPDX-License-Identifier: MIT

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

interface CommandPlan {
  readonly command: string;
  readonly args: string[];
}

interface MacBuildPlan {
  readonly pkgbuild: CommandPlan;
  readonly productbuild: CommandPlan;
  readonly appdmg: CommandPlan;
  readonly dmgPath: string;
  readonly pkgPath: string;
  readonly componentPkgPath: string;
  readonly checksumPath: string;
  readonly appdmgConfigPath: string;
  readonly appdmgConfigContents: string;
}

interface BuildOptions {
  readonly version?: string;
  readonly pkgbuildPath?: string;
  readonly productbuildPath?: string;
  readonly appdmgPath?: string;
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

export function planMacBuild(options: BuildOptions = {}): MacBuildPlan {
  const rootDir = resolveRoot();
  const version = options.version ?? loadPackageVersion(rootDir);
  const distDir = options.distDir ?? path.join(rootDir, 'dist', 'installers', 'macos');
  const payloadRoot = path.join(rootDir, 'deploy', 'installers', 'macos', 'payload');
  const resourcesDir = path.join(rootDir, 'deploy', 'installers', 'macos', 'Resources');
  const scriptsDir = path.join(rootDir, 'deploy', 'installers', 'macos', 'Scripts');
  const distributionXml = path.join(rootDir, 'deploy', 'installers', 'macos', 'Distribution.xml');
  const appdmgTemplate = path.join(rootDir, 'deploy', 'installers', 'macos', 'appdmg.json');
  const componentPkgPath = path.join(distDir, 'staging', 'AtlasSCA.component.pkg');
  const pkgPath = path.join(distDir, `AtlasSCA-${version}.pkg`);
  const dmgPath = path.join(distDir, `AtlasSCA-${version}.dmg`);
  const checksumPath = `${dmgPath}.sha256`;
  const pkgbuildPath = options.pkgbuildPath ?? process.env.PKGBUILD_PATH ?? 'pkgbuild';
  const productbuildPath = options.productbuildPath ?? process.env.PRODUCTBUILD_PATH ?? 'productbuild';
  const appdmgPath = options.appdmgPath ?? process.env.APPDMG_PATH ?? 'appdmg';
  const resolvedConfigPath = path.join(distDir, 'staging', 'appdmg.json');

  const pkgbuildArgs = [
    '--root',
    payloadRoot,
    '--identifier',
    'com.alterra.atlassca',
    '--version',
    version,
    '--install-location',
    '/Applications/Atlas SCA.app',
    '--scripts',
    scriptsDir,
    componentPkgPath
  ];

  const productbuildArgs = [
    '--distribution',
    distributionXml,
    '--resources',
    resourcesDir,
    '--package-path',
    path.dirname(componentPkgPath),
    pkgPath
  ];

  const template = readFileSync(appdmgTemplate, 'utf8');
  const appdmgConfigContents = template.replace('{{PKG_PATH}}', pkgPath);
  const appdmgArgs = [resolvedConfigPath, dmgPath];

  return {
    pkgbuild: { command: pkgbuildPath, args: pkgbuildArgs },
    productbuild: { command: productbuildPath, args: productbuildArgs },
    appdmg: { command: appdmgPath, args: appdmgArgs },
    dmgPath,
    pkgPath,
    componentPkgPath,
    checksumPath,
    appdmgConfigPath: resolvedConfigPath,
    appdmgConfigContents
  };
}

function spawnRunner(plan: CommandPlan): void {
  const result = spawnSync(plan.command, plan.args, { stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(`Command failed: ${plan.command} ${plan.args.join(' ')}`);
  }
}

async function writeChecksum(targetPath: string, checksumPath: string): Promise<void> {
  if (!existsSync(targetPath)) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(targetPath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => {
      const digest = hash.digest('hex');
      writeFileSync(checksumPath, `${digest}  ${path.basename(targetPath)}\n`, 'utf8');
      resolve();
    });
  });
}

export async function buildMacInstaller(options: BuildOptions = {}): Promise<string> {
  const plan = planMacBuild(options);
  mkdirSync(path.dirname(plan.componentPkgPath), { recursive: true });
  mkdirSync(path.dirname(plan.pkgPath), { recursive: true });
  writeFileSync(plan.appdmgConfigPath, plan.appdmgConfigContents, 'utf8');
  rmSync(plan.componentPkgPath, { force: true });
  rmSync(plan.pkgPath, { force: true });
  rmSync(plan.dmgPath, { force: true });
  rmSync(plan.checksumPath, { force: true });
  const runner = options.runner ?? spawnRunner;
  runner(plan.pkgbuild);
  runner(plan.productbuild);
  runner(plan.appdmg);
  await writeChecksum(plan.dmgPath, plan.checksumPath);
  return plan.dmgPath;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildMacInstaller().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
