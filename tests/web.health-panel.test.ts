// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

describe('web health panel', () => {
  const htmlPath = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'health.html');
  const html = readFileSync(htmlPath, 'utf8');

  it('exposes accessible placeholders for queue depth and worker capacity', () => {
    expect(html).toContain('id="queue-depth"');
    expect(html).toContain('id="worker-capacity"');
    expect(html).toContain('aria-live="polite"');
  });

  it('loads data from the v1 health endpoint on an interval', () => {
    expect(html).toContain("fetch('/v1/health'");
    expect(html).toContain('window.setTimeout(scheduleRefresh, 15000)');
  });

  it('renders a list container for the last ten failures', () => {
    expect(html).toContain('id="failure-list"');
    expect(html).toContain('id="failure-empty"');
    expect(html).toContain('Son 10 Hata');
  });
});
