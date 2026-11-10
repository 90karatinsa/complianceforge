// SPDX-License-Identifier: MIT

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    setupFiles: ['tests/setup.ts'],
    // vi.stubEnv ile degistirilen ortam degiskenleri her testten sonra geri alinir.
    unstubEnvs: true
  },
  coverage: {
    enabled: true,
    provider: 'v8',
    reporter: ['text', 'lcov'],
    thresholds: {
      statements: 80,
      branches: 80,
      functions: 80,
      lines: 80
    }
  }
});
