// SPDX-License-Identifier: MIT

import { Buffer } from 'node:buffer';
import { vi } from 'vitest';

vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  return { ...actual };
});

const keytarStore = new Map<string, string>();

vi.mock('keytar', () => ({
  default: {
    setPassword: vi.fn(async (_service: string, _account: string, value: string) => {
      keytarStore.set(`${_service}:${_account}`, value);
      return undefined;
    }),
    getPassword: vi.fn(async (_service: string, _account: string) => {
      return keytarStore.get(`${_service}:${_account}`) ?? null;
    }),
    deletePassword: vi.fn(async (_service: string, _account: string) => {
      return keytarStore.delete(`${_service}:${_account}`);
    })
  }
}));

vi.mock('@fastify/under-pressure', () => ({
  default: vi.fn()
}));

vi.mock('@opentelemetry/api', () => {
  const ROOT_CONTEXT = {};
  const TraceFlags = { NONE: 0, SAMPLED: 1 } as const;
  const SpanStatusCode = { OK: 1, ERROR: 2 } as const;

  const trace = {
    getTracer: vi.fn(() => ({
      startSpan: vi.fn((_name?: string, _options?: unknown, parentContext?: unknown) => {
        const spanContext = (parentContext as { __spanContext?: unknown })?.__spanContext ?? {
          traceId: '0'.repeat(32),
          spanId: '0'.repeat(16),
          traceFlags: TraceFlags.SAMPLED
        };

        return {
          spanContext: () => spanContext,
          setAttribute: vi.fn(),
          setStatus: vi.fn(),
          recordException: vi.fn(),
          end: vi.fn()
        };
      })
    })),
    setSpanContext: vi.fn((_context: unknown, spanContext: unknown) => ({
      __spanContext: spanContext
    })),
    getSpanContext: vi.fn((context: unknown) => (context as { __spanContext?: unknown })?.__spanContext ?? null)
  } as const;

  const propagation = {
    setGlobalPropagator: vi.fn(),
    inject: vi.fn((_ctx: unknown, _carrier: unknown, _setter: unknown) => {}),
    extract: vi.fn((_ctx: unknown, _carrier: unknown, _getter: unknown) => ({
      __spanContext: {
        traceId: '0'.repeat(32),
        spanId: '0'.repeat(16),
        traceFlags: TraceFlags.SAMPLED
      }
    }))
  } as const;

  const otContext = {
    active: vi.fn(() => ROOT_CONTEXT),
    with: vi.fn((_ctx: unknown, fn: (...args: unknown[]) => unknown, ...args: unknown[]) => fn(...args))
  } as const;

  return {
    ROOT_CONTEXT,
    TraceFlags,
    SpanStatusCode,
    context: otContext,
    propagation,
    trace
  };
});

vi.mock('@opentelemetry/core', () => ({
  W3CTraceContextPropagator: class {}
}));

vi.mock('@opentelemetry/exporter-trace-otlp-http', () => ({
  OTLPTraceExporter: class {}
}));

vi.mock('@opentelemetry/resources', () => ({
  Resource: class {
    constructor(public readonly attributes: Record<string, unknown>) {
      this.attributes = attributes;
    }
  }
}));

vi.mock('@opentelemetry/sdk-trace-base', () => ({
  BatchSpanProcessor: class {},
  ConsoleSpanExporter: class {},
  InMemorySpanExporter: class {
    #spans: unknown[] = [];

    export(spans: unknown[], callback: (result: { code: number }) => void): void {
      this.#spans.push(...spans);
      callback({ code: 0 });
    }

    getFinishedSpans(): unknown[] {
      return this.#spans;
    }

    reset(): void {
      this.#spans = [];
    }
  },
  SimpleSpanProcessor: class {}
}));

vi.mock('@opentelemetry/sdk-trace-node', () => ({
  NodeTracerProvider: class {
    addSpanProcessor(): void {}
    getTracer(): { startSpan: ReturnType<typeof vi.fn> } {
      return {
        startSpan: vi.fn(() => ({
          spanContext: () => ({ traceId: '0'.repeat(32), spanId: '0'.repeat(16), traceFlags: 1 }),
          setAttribute: vi.fn(),
          setStatus: vi.fn(),
          recordException: vi.fn(),
          end: vi.fn()
        }))
      };
    }
    register(): void {}
  }
}));

vi.mock('@opentelemetry/semantic-conventions', () => ({
  SemanticResourceAttributes: {
    SERVICE_NAME: 'service.name'
  }
}));

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: class {
    public send = vi.fn();
  },
  GetSecretValueCommand: class {
    public readonly input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  }
}));

const argonHashStore = new Map<string, string>();
const ARGON2_PREFIX = '$argon2id$v=19$m=15360,t=2,p=1$test-salt$';

vi.mock('argon2', () => {
  const hash = vi.fn(async (value: string) => {
    const digest = `${ARGON2_PREFIX}${Buffer.from(value).toString('base64url')}`;
    argonHashStore.set(digest, value);
    return digest;
  });

  const verify = vi.fn(async (digest: string, value: string) => {
    const stored = argonHashStore.get(digest);
    if (stored !== undefined) {
      return stored === value;
    }

    return digest.startsWith('$argon2id$');
  });

  return {
    default: {
      argon2id: 2,
      hash,
      verify
    }
  };
});

const DEFAULT_WEBHOOK_SECRET = Buffer.alloc(32, 0x42).toString('base64');
process.env.WEBHOOK_SECRET_KEY = DEFAULT_WEBHOOK_SECRET;

