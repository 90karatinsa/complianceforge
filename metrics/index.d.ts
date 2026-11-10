export interface MetricsRegistry {
  metrics(): Promise<string>;
  readonly contentType: string;
}

export interface HistogramMetric {
  startTimer(): (labels?: Record<string, string>) => void;
}

export interface QueueDepthMetric {
  set(state: string, value: number): void;
}

export interface CounterMetric {
  inc(labels: Record<string, string>): void;
}

export interface GaugeMetric {
  set(label: string, value: number): void;
}

export interface NoiseGaugeMetric {
  set(input: { total: number; downgraded: number }): void;
}

export interface TotalCounterMetric {
  inc(value: number): void;
}

export interface Metrics {
  readonly registry: MetricsRegistry;
  readonly queueDepthGauge: QueueDepthMetric;
  readonly scanDurationHistogram: HistogramMetric;
  readonly noticeBuildHistogram: HistogramMetric;
  readonly webhookOutcomeCounter: CounterMetric;
  readonly feedImportCounter: CounterMetric;
  readonly vexStateGauge: GaugeMetric;
  readonly vexNoiseGauge: NoiseGaugeMetric;
  readonly vexDowngradedCounter: TotalCounterMetric;
  readonly purgeDurationHistogram: HistogramMetric;
}

export const metrics: Metrics;
export function resetMetrics(): void;
