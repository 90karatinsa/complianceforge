// SPDX-License-Identifier: MIT

import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

const registry = new Registry();
collectDefaultMetrics({ register: registry });

const scanDuration = new Histogram({
  name: 'otomatik_scan_duration_seconds',
  help: 'Duration of completed scan jobs in seconds',
  labelNames: ['status'],
  registers: [registry]
});

const noticeBuildDuration = new Histogram({
  name: 'otomatik_notice_build_seconds',
  help: 'Duration of NOTICE builder executions in seconds',
  labelNames: ['outcome'],
  registers: [registry]
});

const queueDepth = new Gauge({
  name: 'otomatik_scan_queue_depth',
  help: 'Number of scan jobs in the queue by state',
  labelNames: ['state'],
  registers: [registry]
});

const webhookOutcome = new Counter({
  name: 'otomatik_webhook_deliveries_total',
  help: 'Count of webhook delivery outcomes grouped by result',
  labelNames: ['result'],
  registers: [registry]
});

const feedImports = new Counter({
  name: 'otomatik_feed_operations_total',
  help: 'Count of feed activation and rollback operations',
  labelNames: ['action'],
  registers: [registry]
});

const vexGauge = new Gauge({
  name: 'otomatik_vex_statements',
  help: 'Current VEX statements tracked by status',
  labelNames: ['status'],
  registers: [registry]
});

const purgeDuration = new Histogram({
  name: 'otomatik_workspace_purge_seconds',
  help: 'Duration of workspace purge operations in seconds',
  registers: [registry]
});

const vexNoiseRatio = new Gauge({
  name: 'otomatik_vex_noise_reduction_ratio',
  help: 'Ratio of vulnerabilities downgraded via VEX statements',
  registers: [registry]
});

const vexDowngradedTotal = new Counter({
  name: 'otomatik_vex_downgraded_total',
  help: 'Total vulnerabilities downgraded as not affected due to VEX statements',
  registers: [registry]
});

queueDepth.labels('waiting').set(0);
queueDepth.labels('active').set(0);
queueDepth.labels('delayed').set(0);

export const metrics = {
  registry,
  queueDepthGauge: {
    set(state, value) {
      queueDepth.labels(state).set(value);
    }
  },
  scanDurationHistogram: {
    startTimer() {
      const end = scanDuration.startTimer();
      return (labels) => {
        end(labels);
      };
    }
  },
  noticeBuildHistogram: {
    startTimer() {
      const end = noticeBuildDuration.startTimer();
      return (labels) => {
        end(labels);
      };
    }
  },
  webhookOutcomeCounter: {
    inc(labels) {
      webhookOutcome.inc(labels);
    }
  },
  feedImportCounter: {
    inc(labels) {
      feedImports.inc(labels);
    }
  },
  vexStateGauge: {
    set(status, value) {
      vexGauge.labels(status).set(value);
    }
  },
  vexNoiseGauge: {
    set({ total, downgraded }) {
      const ratio = total > 0 ? downgraded / total : 0;
      vexNoiseRatio.set(ratio);
    }
  },
  vexDowngradedCounter: {
    inc(value) {
      vexDowngradedTotal.inc(typeof value === 'number' ? value : 0);
    }
  },
  purgeDurationHistogram: {
    startTimer() {
      const end = purgeDuration.startTimer();
      return () => {
        end();
      };
    }
  }
};

export function resetMetrics() {
  queueDepth.reset();
  scanDuration.reset();
  webhookOutcome.reset();
  noticeBuildDuration.reset();
  feedImports.reset();
  vexGauge.reset();
  vexNoiseRatio.reset();
  vexDowngradedTotal.reset();
  purgeDuration.reset();
  queueDepth.labels('waiting').set(0);
  queueDepth.labels('active').set(0);
  queueDepth.labels('delayed').set(0);
}
