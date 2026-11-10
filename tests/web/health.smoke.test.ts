// SPDX-License-Identifier: MIT
/// <reference lib="dom" />
/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';
import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';

interface MockFetchResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

type FetchMock = Mock<[RequestInfo | URL, RequestInit | undefined], Promise<MockFetchResponse>>;

type ConsoleSpy = Mock<[unknown?], void>;

interface PanelHarness {
  dom: JSDOM;
  window: Window & typeof globalThis;
  document: Document;
  consoleError: ConsoleSpy;
}

const html = readFileSync(join(process.cwd(), 'web/health.html'), 'utf8');

const waitForStatus = async (document: Document, expected: string) => {
  const started = Date.now();
  const timeoutMs = 1_000;

  // Poll until the badge reflects the expected status or timeout occurs
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const status = document.getElementById('status-label')?.getAttribute('data-status');
    if (status === expected) {
      return;
    }

    if (Date.now() - started > timeoutMs) {
      throw new Error(`Beklenen durum ${expected} değerine ulaşılamadı, son durum: ${status ?? 'unknown'}`);
    }

    await new Promise<void>((resolve) => {
      setTimeout(resolve, 10);
    });
  }
};

const buildDom = (fetchMock: FetchMock): PanelHarness => {
  let consoleSpy: ConsoleSpy | undefined;

  const dom = new JSDOM(html, {
    url: 'https://panel.alterra.local',
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    beforeParse(window: Window & typeof globalThis) {
      consoleSpy = vi.fn<[unknown?], void>();
      const boundFetch = ((input: RequestInfo | URL, init?: RequestInit) => fetchMock(input, init)) as typeof window.fetch;
      window.fetch = boundFetch;
      window.console.error = consoleSpy as unknown as typeof window.console.error;
    }
  });

  if (!consoleSpy) {
    throw new Error('Console spy initialize edilemedi');
  }

  const typedDom = dom;
  const { window } = typedDom;
  const document = window.document;
  const consoleError: ConsoleSpy = consoleSpy;

  return { dom: typedDom, window, document, consoleError };
};

describe('health panel', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('renders accessible healthy state with expected visual tokens', async () => {
    const fetchMock: FetchMock = vi.fn(() =>
      Promise.resolve<MockFetchResponse>({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            status: 'healthy',
            details: { summary: 'Platform bileşenleri sağlıklı.' },
            queue: { waiting: 2, active: 1, delayed: 0 },
            worker_capacity: 6,
            checked_at: new Date().toISOString(),
            last_failures: [],
            slo: { summary_p95_ms: 280, orchestration_p95_ms: 540 }
          })
      })
    );

    const harness = buildDom(fetchMock);
    await waitForStatus(harness.document, 'healthy');

    expect(fetchMock).toHaveBeenCalledWith('/v1/health', expect.objectContaining({ cache: 'no-store' }));

    const card = harness.document.querySelector('.card');
    expect(card?.getAttribute('role')).toBe('region');
    expect(card?.getAttribute('aria-live')).toBe('polite');

    const badge = harness.document.getElementById('status-label');
    expect(badge?.textContent?.trim()).toBe('Sağlıklı');

    const styleContent = harness.document.querySelector('style')?.textContent ?? '';
    expect(styleContent).toContain('color: #5eead4');
    expect(styleContent).toContain('background: rgba(45, 212, 191, 0.2)');

    const failureList = harness.document.getElementById('failure-list');
    expect(failureList?.getAttribute('aria-live')).toBe('polite');
    expect(failureList?.getAttribute('aria-busy')).toBe('false');

    const summaryP95 = harness.document.getElementById('summary-p95');
    expect(summaryP95?.textContent).toContain('280');
    const orchestrationP95 = harness.document.getElementById('orchestration-p95');
    expect(orchestrationP95?.textContent).toContain('540');

    harness.window.close();
  });

  it('announces down state when fetch fails', async () => {
    const fetchMock: FetchMock = vi.fn(() =>
      Promise.reject<MockFetchResponse>(new Error('network unreachable'))
    );

    const harness = buildDom(fetchMock);

    await waitForStatus(harness.document, 'down');

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const badge = harness.document.getElementById('status-label');
    expect(badge?.textContent?.trim()).toBe('Erişim Yok');

    const description = harness.document.getElementById('status-description');
    expect(description?.textContent).toContain('Health API yanıt vermiyor');

    const failureEmpty = harness.document.getElementById('failure-empty');
    expect(failureEmpty?.hidden).toBe(false);

    expect(harness.consoleError).toHaveBeenCalled();

    harness.window.close();
  });

  it('avoids overlapping refresh requests during long polls', async () => {
    vi.useFakeTimers();
    try {
      let releaseResponse: ((value: MockFetchResponse) => void) | undefined;
      const fetchPromise = new Promise<MockFetchResponse>((resolve) => {
        releaseResponse = resolve;
      });

      const fetchMock: FetchMock = vi.fn(() => fetchPromise);
      const harness = buildDom(fetchMock);

      expect(fetchMock).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(15000);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      releaseResponse?.({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            status: 'healthy',
            queue: { waiting: 0, active: 0, delayed: 0 },
            worker_capacity: 4,
            checked_at: new Date().toISOString(),
            last_failures: [],
            slo: { summary_p95_ms: 300, orchestration_p95_ms: 520 }
          })
      });

      await Promise.resolve();

      await vi.advanceTimersByTimeAsync(15000);
      expect(fetchMock).toHaveBeenCalledTimes(2);

      harness.window.close();
    } finally {
      vi.useRealTimers();
    }
  });
});
