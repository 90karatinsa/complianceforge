// SPDX-License-Identifier: MIT

import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

type ManagedProcess = {
  readonly name: string;
  readonly child: ReturnType<typeof spawn>;
};

export function spawnNpm(name: string, args: string[]): ManagedProcess {
  const command = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const env = { ...process.env, NODE_ENV: 'development' };
  const child = spawn(command, args, { stdio: 'inherit', env });
  return { name, child };
}

export function startDevProcesses(): ManagedProcess[] {
  return [
    spawnNpm('api', ['run', 'dev:api']),
    spawnNpm('worker', ['run', 'dev:worker'])
  ];
}

async function main(): Promise<void> {
  const processes = startDevProcesses();

  let shuttingDown = false;

  const shutdown = (signal?: NodeJS.Signals | number) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    for (const entry of processes) {
      if (!entry.child.killed) {
        try {
          entry.child.kill(typeof signal === 'string' ? signal : 'SIGTERM');
        } catch {
          entry.child.kill();
        }
      }
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  const exitCodes = await Promise.all(
    processes.map(
      (entry) =>
        new Promise<number>((resolve) => {
          entry.child.on('exit', (code) => {
            if (!shuttingDown && code && code !== 0) {
              shutdown(code);
            }
            resolve(code ?? 0);
          });
          entry.child.on('error', (error) => {
            console.error(`[dev] ${entry.name} failed to start: ${String(error)}`);
            shutdown();
            resolve(1);
          });
        })
    )
  );

  const firstFailure = exitCodes.find((code) => code !== 0) ?? 0;
  process.exit(firstFailure);
}

const invokedAsScript = (() => {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  try {
    return pathToFileURL(entry).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
  main().catch((error) => {
    console.error('[dev] Unexpected failure', error);
    process.exit(1);
  });
}
