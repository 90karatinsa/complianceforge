// SPDX-License-Identifier: MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { metrics, resetMetrics } from '../metrics/index.js';

vi.mock('prom-client', () => {
  const gaugeValues = new Map<string, number>();
  const counterValues = new Map<string, number>();

  class MockGauge {
    public readonly name: string;

    constructor(options: { name?: string }) {
      this.name = options.name ?? 'mock_gauge';
    }

    startTimer() {
      return () => {};
    }

    labels() {
      return this;
    }

    set(value: number) {
      gaugeValues.set(this.name, value);
    }

    reset() {
      gaugeValues.delete(this.name);
    }
  }

  class MockCounter {
    public readonly name: string;

    constructor(options: { name?: string }) {
      this.name = options.name ?? 'mock_counter';
    }

    inc(value?: number) {
      const current = counterValues.get(this.name) ?? 0;
      counterValues.set(this.name, current + (typeof value === 'number' ? value : 0));
    }

    labels() {
      return this;
    }

    reset() {
      counterValues.delete(this.name);
    }
  }

  class MockRegistry {
    metrics() {
      const gaugeLines = Array.from(gaugeValues.entries()).map(([name, value]) => `${name} ${value}`);
      const counterLines = Array.from(counterValues.entries()).map(([name, value]) => `${name} ${value}`);
      return Promise.resolve([...gaugeLines, ...counterLines].join('\n'));
    }

    get contentType(): string {
      return 'text/plain';
    }
  }

  return {
    Counter: MockCounter,
    Gauge: MockGauge,
    Histogram: MockGauge,
    Registry: MockRegistry,
    collectDefaultMetrics: () => {}
  } satisfies Record<string, unknown>;
});

async function getMetricLine(name: string): Promise<string | undefined> {
  const output = await metrics.registry.metrics();
  return output
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith(name));
}

describe('VEX noise metrics', () => {
  afterEach(() => {
    resetMetrics();
  });

  it('tracks noise reduction ratio and downgraded counter', async () => {
    metrics.vexNoiseGauge.set({ total: 0, downgraded: 5 });
    metrics.vexDowngradedCounter.inc(2);
    metrics.vexNoiseGauge.set({ total: 10, downgraded: 4 });
    metrics.vexDowngradedCounter.inc(3);

    const ratioLine = await getMetricLine('otomatik_vex_noise_reduction_ratio');
    const downgradedLine = await getMetricLine('otomatik_vex_downgraded_total');

    expect(ratioLine).toBeDefined();
    expect(ratioLine?.endsWith('0.4')).toBe(true);
    expect(downgradedLine).toBeDefined();
    expect(downgradedLine?.endsWith('5')).toBe(true);
  });
});
