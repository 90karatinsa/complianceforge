// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { createSiemDispatcher } from '../worker/src/integrations/siem.ts';

describe('SIEM dispatcher', () => {
  it('rejects destinations that are not HTTPS', () => {
    expect(() =>
      createSiemDispatcher(
        [{ type: 'splunk', url: 'http://splunk.example.com', token: 'token' }],
        { fetch: vi.fn(), wait: async () => {} }
      )
    ).toThrow(/HTTPS/);

    expect(() =>
      createSiemDispatcher(
        [{ type: 'elastic', url: 'not-a-url', token: 'token' }],
        { fetch: vi.fn(), wait: async () => {} }
      )
    ).toThrow(/valid HTTPS URL/);
  });

  it('sends events to all configured destinations with appropriate headers', async () => {
    const fetchMock = vi
      .fn<Promise<Response>, Parameters<typeof fetch>>()
      .mockResolvedValue({ ok: true, status: 200, text: async () => '' } as unknown as Response);

    const dispatcher = createSiemDispatcher(
      [
        { type: 'splunk', url: 'https://splunk.example.com/collector', token: 'splunk-token', dataset: 'security' },
        { type: 'sentinel', url: 'https://sentinel.example.com/api', token: 'sentinel-key' },
        { type: 'elastic', url: 'https://elastic.example.com/ingest', token: 'elastic-key' }
      ],
      { fetch: fetchMock, wait: async () => {} }
    );

    await dispatcher.publish({
      type: 'scan.completed',
      tenantId: 'tenant-123',
      projectId: 'project-abc',
      scanId: 'scan-xyz',
      policyResult: 'pass',
      totalVulnerabilities: 4,
      downgradedByVex: 2,
      timestamp: '2024-01-01T00:00:00.000Z',
      metadata: { policy_reasons: ['threshold'] }
    });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const [splunkCall, sentinelCall, elasticCall] = fetchMock.mock.calls;

    expect((splunkCall?.[1] as { headers?: Record<string, string> } | undefined)?.headers?.Authorization).toBe(
      'Splunk splunk-token'
    );
    expect(JSON.parse((splunkCall?.[1] as { body?: string } | undefined)?.body ?? '{}')).toMatchObject({
      event: expect.objectContaining({ event_type: 'scan.completed', dataset: 'security' })
    });

    expect((sentinelCall?.[1] as { headers?: Record<string, string> } | undefined)?.headers?.Authorization).toBe(
      'SharedKey sentinel-key'
    );
    expect(JSON.parse((sentinelCall?.[1] as { body?: string } | undefined)?.body ?? '{}')).toMatchObject({
      records: [expect.objectContaining({ event_type: 'scan.completed' })]
    });

    expect((elasticCall?.[1] as { headers?: Record<string, string> } | undefined)?.headers?.Authorization).toBe(
      'ApiKey elastic-key'
    );
  });

  it('dispatches to destinations concurrently', async () => {
    const deferreds: Array<ReturnType<typeof createDeferred<Response>>> = [];
    const fetchMock = vi.fn(() => {
      const deferred = createDeferred<Response>();
      deferreds.push(deferred);
      return deferred.promise;
    });

    const dispatcher = createSiemDispatcher(
      [
        { type: 'splunk', url: 'https://splunk.example.com/collector', token: 'splunk-token' },
        { type: 'sentinel', url: 'https://sentinel.example.com/api', token: 'sentinel-key' },
        { type: 'elastic', url: 'https://elastic.example.com/ingest', token: 'elastic-key' }
      ],
      { fetch: fetchMock, wait: async () => {} }
    );

    const publishPromise = dispatcher.publish({
      type: 'scan.completed',
      tenantId: 'tenant-123',
      projectId: 'project-abc',
      scanId: 'scan-xyz',
      policyResult: 'pass',
      totalVulnerabilities: 1,
      downgradedByVex: 0,
      timestamp: '2024-01-01T00:00:00.000Z'
    });

    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(3);

    for (const deferred of deferreds) {
      deferred.resolve({ ok: true, status: 200, text: async () => '' } as unknown as Response);
    }

    await publishPromise;
  });

  it('retries failed deliveries and surfaces sanitized errors', async () => {
    const fetchMock = vi
      .fn<Promise<Response>, Parameters<typeof fetch>>()
      .mockResolvedValue({ ok: false, status: 503, text: async () => 'service down' } as unknown as Response);
    const waitMock = vi.fn(() => Promise.resolve());

    const dispatcher = createSiemDispatcher(
      [{ type: 'splunk', url: 'https://splunk.internal.example.com/collector', token: 'secret-token' }],
      { fetch: fetchMock, wait: waitMock, maxAttempts: 2, baseDelayMs: 200 }
    );

    let caughtError: Error | null = null;
    await dispatcher
      .publish({
        type: 'scan.failed',
        tenantId: 'tenant-123',
        projectId: 'project-abc',
        scanId: 'scan-xyz',
        policyResult: 'error',
        totalVulnerabilities: 0,
        downgradedByVex: 0,
        timestamp: '2024-01-01T00:00:00.000Z',
        metadata: { error: 'timeout' }
      })
      .catch((error: Error) => {
        caughtError = error;
      });

    expect(waitMock).toHaveBeenCalledWith(200);
    expect(waitMock).toHaveBeenCalledTimes(1);
    expect(caughtError).toBeInstanceOf(Error);
    expect(caughtError?.message).not.toContain('secret-token');
    expect(caughtError?.message).toContain('splunk');
    expect(caughtError?.message).toContain('https://splunk.internal.example.com/collector');
  });
});

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}
