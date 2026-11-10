// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import { metrics, resetMetrics } from '../metrics/index.js';

describe('metrics module', () => {
  it('exposes extended metric helpers', () => {
    expect(metrics.noticeBuildHistogram).toBeDefined();
    expect(metrics.feedImportCounter).toBeDefined();
    expect(metrics.vexStateGauge).toBeDefined();
    expect(metrics.purgeDurationHistogram).toBeDefined();

    const endTimer = metrics.noticeBuildHistogram.startTimer();
    endTimer({ outcome: 'test' });
    metrics.feedImportCounter.inc({ action: 'test' });
    metrics.vexStateGauge.set('status', 1);
    const purgeTimer = metrics.purgeDurationHistogram.startTimer();
    purgeTimer();

    resetMetrics();
  });
});
