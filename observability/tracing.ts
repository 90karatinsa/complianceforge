// SPDX-License-Identifier: MIT

import { randomBytes } from 'node:crypto';

type ExceptionRecord = { message: string };

export type SpanStatus = 'ok' | 'error';

export interface SpanContext {
  readonly traceId: string;
  readonly spanId: string;
  readonly sampled: boolean;
}

export interface SpanRecord {
  readonly name: string;
  readonly context: SpanContext;
  readonly parentSpanId: string | null;
  readonly attributes: Record<string, unknown>;
  status: SpanStatus;
  statusMessage?: string;
  readonly startTime: number;
  endTime?: number;
  readonly exceptions: ExceptionRecord[];
}

export interface SpanHandle {
  readonly context: SpanContext;
  setAttribute(key: string, value: unknown): void;
  setStatus(status: SpanStatus, message?: string): void;
  recordException(error: unknown): void;
  end(): void;
}

export interface Tracer {
  startSpan(
    name: string,
    options?: { attributes?: Record<string, unknown>; parentContext?: SpanContext | null }
  ): SpanHandle;
  inject(carrier: Record<string, string>, context: SpanContext): void;
  extract(carrier: Record<string, string | string[] | undefined>): SpanContext | null;
  getFinishedSpans(): ReadonlyArray<SpanRecord>;
}

function generateTraceId(): string {
  return randomBytes(16).toString('hex');
}

function generateSpanId(): string {
  return randomBytes(8).toString('hex');
}

class RecordingSpan implements SpanHandle {
  private readonly tracer: RecordingTracer;
  private readonly record: SpanRecord;
  private ended = false;

  constructor(tracer: RecordingTracer, record: SpanRecord) {
    this.tracer = tracer;
    this.record = record;
  }

  get context(): SpanContext {
    return this.record.context;
  }

  setAttribute(key: string, value: unknown): void {
    this.record.attributes[key] = value;
  }

  setStatus(status: SpanStatus, message?: string): void {
    this.record.status = status;
    this.record.statusMessage = message;
  }

  recordException(error: unknown): void {
    if (error instanceof Error) {
      this.record.exceptions.push({ message: error.message });
      return;
    }
    if (typeof error === 'object' && error !== null && 'message' in (error as Record<string, unknown>)) {
      const messageValue = (error as { message?: unknown }).message;
      this.record.exceptions.push({ message: typeof messageValue === 'string' ? messageValue : String(error) });
      return;
    }
    this.record.exceptions.push({ message: String(error) });
  }

  end(): void {
    if (this.ended) {
      return;
    }
    this.ended = true;
    this.record.endTime = Date.now();
    this.tracer.recordFinishedSpan(this.record);
  }
}

class RecordingTracer implements Tracer {
  private readonly serviceName: string;
  private readonly finished: SpanRecord[] = [];

  constructor(serviceName: string) {
    this.serviceName = serviceName;
  }

  startSpan(
    name: string,
    options?: { attributes?: Record<string, unknown>; parentContext?: SpanContext | null }
  ): SpanHandle {
    const parent = options?.parentContext ?? null;
    const traceId = parent?.traceId ?? generateTraceId();
    const spanId = generateSpanId();
    const context: SpanContext = { traceId, spanId, sampled: true };
    const attributes: Record<string, unknown> = {
      'service.name': this.serviceName,
      ...(options?.attributes ?? {})
    };
    const record: SpanRecord = {
      name,
      context,
      parentSpanId: parent?.spanId ?? null,
      attributes,
      status: 'ok',
      startTime: Date.now(),
      exceptions: []
    };
    return new RecordingSpan(this, record);
  }

  inject(carrier: Record<string, string>, context: SpanContext): void {
    const traceparent = `00-${context.traceId}-${context.spanId}-${context.sampled ? '01' : '00'}`;
    carrier.traceparent = traceparent;
  }

  extract(carrier: Record<string, string | string[] | undefined>): SpanContext | null {
    const value = carrier.traceparent;
    const header = Array.isArray(value) ? value[0] : value;
    if (typeof header !== 'string') {
      return null;
    }
    const match = header.match(/^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/iu);
    if (!match) {
      return null;
    }
    return {
      traceId: match[1].toLowerCase(),
      spanId: match[2].toLowerCase(),
      sampled: match[3].toLowerCase() === '01'
    } satisfies SpanContext;
  }

  getFinishedSpans(): ReadonlyArray<SpanRecord> {
    return this.finished.map((span) => ({
      name: span.name,
      context: span.context,
      parentSpanId: span.parentSpanId,
      attributes: { ...span.attributes },
      status: span.status,
      statusMessage: span.statusMessage,
      startTime: span.startTime,
      endTime: span.endTime,
      exceptions: span.exceptions.map((entry) => ({ ...entry }))
    }));
  }

  recordFinishedSpan(record: SpanRecord): void {
    this.finished.push({
      name: record.name,
      context: record.context,
      parentSpanId: record.parentSpanId,
      attributes: { ...record.attributes },
      status: record.status,
      statusMessage: record.statusMessage,
      startTime: record.startTime,
      endTime: record.endTime,
      exceptions: record.exceptions.map((entry) => ({ ...entry }))
    });
  }
}

class NoopSpan implements SpanHandle {
  private readonly spanContext: SpanContext;

  constructor(parentContext?: SpanContext | null) {
    if (parentContext) {
      this.spanContext = {
        traceId: parentContext.traceId,
        spanId: generateSpanId(),
        sampled: false
      };
    } else {
      this.spanContext = {
        traceId: generateTraceId(),
        spanId: generateSpanId(),
        sampled: false
      };
    }
  }

  get context(): SpanContext {
    return this.spanContext;
  }

  setAttribute(): void {
    // no-op
  }

  setStatus(): void {
    // no-op
  }

  recordException(): void {
    // no-op
  }

  end(): void {
    // no-op
  }
}

class NoopTracer implements Tracer {
  startSpan(
    _name: string,
    options?: { attributes?: Record<string, unknown>; parentContext?: SpanContext | null }
  ): SpanHandle {
    return new NoopSpan(options?.parentContext ?? null);
  }

  inject(): void {
    // no-op
  }

  extract(): SpanContext | null {
    return null;
  }

  getFinishedSpans(): ReadonlyArray<SpanRecord> {
    return [];
  }
}

export interface CreateTracerOptions {
  readonly enabled?: boolean;
}

export function createTracer(serviceName: string, options?: CreateTracerOptions): Tracer {
  if (!options?.enabled) {
    return new NoopTracer();
  }
  return new RecordingTracer(serviceName);
}
