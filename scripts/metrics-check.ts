// SPDX-License-Identifier: MIT

import { metrics } from '../metrics/index.js';

async function main(): Promise<void> {
  const output = await metrics.registry.metrics();
  process.stdout.write(output);
}

main().catch((error: unknown) => {
  const failure = error instanceof Error ? error : new Error(String(error));
  console.error('Metrics check failed', failure);
  process.exitCode = 1;
});
