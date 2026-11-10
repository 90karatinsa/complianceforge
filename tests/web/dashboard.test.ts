// SPDX-License-Identifier: MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const SUMMARY_RESPONSE = {
  data: {
    total_scans: 10,
    policy: { pass: 7, warn: 2, fail: 1 },
    license_violations: 3,
    vex_noise_reduction: { total: 4, downgraded: 2, ratio: 0.5 }
  }
};

const HEALTH_RESPONSE = {
  status: 'healthy',
  queue: { waiting: 5, delayed: 1 },
  notice: { ready: 2 },
  feeds: { active_version: 'feed-1', last_imported_at: '2024-07-01T10:00:00.000Z', signature_status: 'İmza doğrulandı' },
  vex: { breakdown: [] }
};

const HEALTH_FAILURE_RESPONSE = {
  status: 'degraded',
  queue: { waiting: 8, delayed: 2 },
  notice: { ready: 1 },
  feeds: {
    active_version: 'feed-1',
    last_imported_at: '2024-07-02T08:30:00.000Z',
    signature_status: 'İmza doğrulanamadı'
  },
  vex: { breakdown: [] }
};

const HEALTH_UNKNOWN_RESPONSE = {
  status: 'healthy',
  queue: { waiting: 2, delayed: 0 },
  notice: { ready: 0 },
  feeds: {
    active_version: null,
    last_imported_at: null,
    signature_status: null
  },
  vex: { breakdown: [] }
};

const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

describe('dashboard page', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('hydrates metrics from health and summary endpoints', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/reports/summary')) {
        return jsonResponse(SUMMARY_RESPONSE);
      }
      if (url === '/v1/health') {
        return jsonResponse(HEALTH_RESPONSE);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('dashboard.html', { fetchImplementation: fetchMock });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const document = dom.window.document;
    expect(document.querySelector('[data-metric="policy-failures"]')?.textContent).toBe('1');
    expect(document.querySelector('[data-metric="legal-queue"]')?.textContent).toBe('3');
    expect(document.querySelector('[data-metric="vex-coverage"]')?.textContent).toBe('50%');
    expect(document.querySelector('[data-metric="notice-ready"]')?.textContent).toBe('9');
    expect(document.querySelector('[data-field="active-version"]')?.textContent).toBe('feed-1');
    const signatureField = document.querySelector('[data-field="signature-status"]');
    expect(signatureField?.textContent).toBe('İmza doğrulandı');
    expect(signatureField?.classList.contains('status-warning')).toBe(false);
  });

  it('shows fallback values when summary endpoint fails', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/reports/summary')) {
        return new Response(null, { status: 503 });
      }
      if (url === '/v1/health') {
        return jsonResponse(HEALTH_FAILURE_RESPONSE);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('dashboard.html', { fetchImplementation: fetchMock });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const document = dom.window.document;
    expect(document.querySelector('[data-metric="policy-failures"]')?.textContent).toBe('8');
    expect(document.querySelector('[data-metric="legal-queue"]')?.textContent).toBe('2');
    const signatureField = document.querySelector('[data-field="signature-status"]');
    expect(signatureField?.textContent).toBe('İmza doğrulanamadı');
    expect(signatureField?.classList.contains('status-warning')).toBe(true);
  });

  it('treats HTTP 503 health responses as degraded payloads', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/reports/summary')) {
        return jsonResponse(SUMMARY_RESPONSE);
      }
      if (url === '/v1/health') {
        return jsonResponse(HEALTH_FAILURE_RESPONSE, 503);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('dashboard.html', { fetchImplementation: fetchMock });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const document = dom.window.document;
    const errorBanner = document.querySelector('[data-health-error]');
    expect(errorBanner instanceof dom.window.HTMLElement && errorBanner.hidden).toBe(true);
    const signatureField = document.querySelector('[data-field="signature-status"]');
    expect(signatureField?.textContent).toBe('İmza doğrulanamadı');
    expect(signatureField?.classList.contains('status-warning')).toBe(true);
  });

  it('renders Bilinmiyor when feed verification data is missing', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/reports/summary')) {
        return jsonResponse(SUMMARY_RESPONSE);
      }
      if (url === '/v1/health') {
        return jsonResponse(HEALTH_UNKNOWN_RESPONSE);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('dashboard.html', { fetchImplementation: fetchMock });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const document = dom.window.document;
    const signatureField = document.querySelector('[data-field="signature-status"]');
    expect(signatureField?.textContent).toBe('Bilinmiyor');
    expect(signatureField?.classList.contains('status-warning')).toBe(false);
    expect(document.querySelector('[data-field="last-import"]')?.textContent).toBe('—');
  });
});
