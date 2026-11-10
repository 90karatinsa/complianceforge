// SPDX-License-Identifier: MIT

import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

interface CommandPlan {
  readonly command: string;
  readonly args: string[];
}

interface WindowsBuildPlan {
  readonly candle: CommandPlan;
  readonly light: CommandPlan;
  readonly sign?: CommandPlan;
  readonly outputMsi: string;
  readonly checksumPath: string;
  readonly offlineGateExpectation: string;
}

interface BuildOptions {
  readonly version?: string;
  readonly candlePath?: string;
  readonly lightPath?: string;
  readonly signtoolPath?: string;
  readonly certificatePath?: string;
  readonly timestampUrl?: string;
  readonly offlineToken?: string;
  readonly runner?: (descriptor: CommandPlan) => void;
  readonly distDir?: string;
  readonly payloadDir?: string;
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

function normalizeWindowsPath(targetPath: string): string {
  return targetPath.replace(/\\/gu, '/').replace(/\//gu, '\\');
}

export function planWindowsBuild(options: BuildOptions = {}): WindowsBuildPlan {
  const rootDir = resolveRoot();
  const version = options.version ?? loadPackageVersion(rootDir);
  const distDir = options.distDir ?? path.join(rootDir, 'dist', 'installers', 'windows');
  const payloadDir = options.payloadDir ?? path.join(rootDir, 'deploy', 'installers', 'windows', 'payload');
  const candlePath = options.candlePath ?? process.env.WIX_CANDLE_PATH ?? 'candle';
  const lightPath = options.lightPath ?? process.env.WIX_LIGHT_PATH ?? 'light';
  const signtoolPath = options.signtoolPath ?? process.env.SIGNTOOL_PATH ?? 'signtool';
  const certificatePath = options.certificatePath ?? process.env.SIGNTOOL_CERT_PATH;
  const timestampUrl = options.timestampUrl ?? process.env.SIGNTOOL_TIMESTAMP_URL;
  const offlineToken = options.offlineToken ?? 'verified-offline';
  const offlineGateExpectation = createHash('sha256').update(offlineToken).digest('hex');
  const wxsPath = path.join(rootDir, 'deploy', 'installers', 'windows', 'Product.wxs');
  const eulaPath = path.join(rootDir, 'deploy', 'installers', 'windows', 'License.rtf');
  const wixobjPath = path.join(distDir, 'Product.wixobj');
  const msiPath = path.join(distDir, `AtlasSCA-${version}.msi`);

  const candleArgs = [
    `-dProductVersion=${version}`,
    `-dEulaPath=${normalizeWindowsPath(eulaPath)}`,
    `-dPayloadDir=${normalizeWindowsPath(payloadDir)}`,
    `-dOfflineGateExpectation=${offlineGateExpectation}`,
    '-out',
    wixobjPath,
    wxsPath
  ];

  const lightArgs = [
    '-ext',
    'WixUIExtension',
    '-ext',
    'WixUtilExtension',
    wixobjPath,
    '-o',
    msiPath
  ];

  let signPlan: CommandPlan | undefined;
  if (certificatePath) {
    const signArgs = ['sign', '/fd', 'SHA256', '/f', certificatePath, '/v', msiPath];
    if (timestampUrl) {
      signArgs.push('/tr', timestampUrl, '/td', 'SHA256');
    }
    signPlan = {
      command: signtoolPath,
      args: signArgs
    };
  }

  return {
    candle: { command: candlePath, args: candleArgs },
    light: { command: lightPath, args: lightArgs },
    sign: signPlan,
    outputMsi: msiPath,
    checksumPath: `${msiPath}.sha256`,
    offlineGateExpectation
  };
}

function spawnRunner(plan: CommandPlan): void {
  const result = spawnSync(plan.command, plan.args, { stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(`Command failed: ${plan.command} ${plan.args.join(' ')}`);
  }
}

export async function buildWindowsInstaller(options: BuildOptions = {}): Promise<string> {
  const plan = planWindowsBuild(options);
  mkdirSync(path.dirname(plan.outputMsi), { recursive: true });
  rmSync(plan.outputMsi, { force: true });
  rmSync(plan.checksumPath, { force: true });
  const runner = options.runner ?? spawnRunner;
  runner(plan.candle);
  runner(plan.light);
  if (plan.sign) {
    runner(plan.sign);
  }
  const hash = createHash('sha256');
  hash.update(readFileSync(plan.outputMsi));
  const digest = hash.digest('hex');
  const checksumBody = `${digest}  ${path.basename(plan.outputMsi)}\n`;
  writeFileSync(plan.checksumPath, checksumBody, 'utf8');
  return plan.outputMsi;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildWindowsInstaller().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
