// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const SUMMARY_RESPONSE = {
  data: {
    total_scans: 42,
    policy: { pass: 30, warn: 8, fail: 4 },
    license_violations: 6,
    average_duration_ms: 905,
    vulnerabilities: {
      critical: 2,
      high: 3,
      medium: 4,
      low: 5
    },
    vex_noise_reduction: {
      total: 12,
      downgraded: 5,
      ratio: 0.4166
    }
  }
};

const PROJECTS_RESPONSE = {
  data: [
    { id: 'proj-1', name: 'Çekirdek Platform' },
    { id: 'proj-2', name: 'Mobil' }
  ]
};

const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

describe('reports page', () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders metrics and export link from summary API', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';

      if (url.startsWith('/v1/projects')) {
        return jsonResponse(PROJECTS_RESPONSE);
      }

      if (url.startsWith('/v1/reports/summary')) {
        expect(url).toContain('tenant_id=55555555-5555-4555-8555-555555555555');
        return jsonResponse(SUMMARY_RESPONSE);
      }

      return jsonResponse({}, 404);
    });

    const dom = loadPage('reports.html', { fetchImplementation: fetchMock });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const document = dom.window.document;

    expect(fetchMock).toHaveBeenCalledWith('/v1/projects?limit=200', expect.anything());
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/v1/reports/summary?tenant_id='),
      expect.objectContaining({ headers: { Accept: 'application/json' } })
    );

    expect(document.querySelector('[data-metric="total-scans"]')?.textContent).toBe('42');
    expect(document.querySelector('[data-metric="policy-breakdown"]')?.textContent).toBe('30 / 8 / 4');
    expect(document.querySelector('[data-metric="avg-duration"]')?.textContent).toBe('905 ms');
    expect(document.querySelector('[data-vuln="critical"]')?.textContent).toBe('2');
    expect(document.querySelector('[data-vex="ratio"]')?.textContent).toBe('42%');

    const exportLink = document.querySelector('[data-export]') as HTMLAnchorElement | null;
    expect(exportLink?.getAttribute('aria-disabled')).toBe('false');
    expect(exportLink?.href).toContain('/v1/reports/export?tenant_id=55555555-5555-4555-8555-555555555555');
  });

  it('shows failure state when summary request fails', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname : '';
      if (url.startsWith('/v1/projects')) {
        return jsonResponse(PROJECTS_RESPONSE);
      }
      return new Response(null, { status: 503 });
    });

    const dom = loadPage('reports.html', { fetchImplementation: fetchMock });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const document = dom.window.document;
    const statusRegion = document.querySelector('[data-status]');

    expect(statusRegion?.textContent).toContain('Rapor verileri alınamadı');
    expect(document.querySelector('[data-metric="total-scans"]')?.textContent).toBe('--');
    expect(document.querySelector('[data-export]')?.getAttribute('aria-disabled')).toBe('true');
  });

  it('schedules auto refresh when toggle is enabled', async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
        if (url.startsWith('/v1/projects')) {
          return jsonResponse(PROJECTS_RESPONSE);
        }
        if (url.startsWith('/v1/reports/summary')) {
          return jsonResponse(SUMMARY_RESPONSE);
        }
        return jsonResponse({});
      })
      .mockName('fetch');

    const dom = loadPage('reports.html', { fetchImplementation: fetchMock });
    await vi.runAllTimersAsync();

    const document = dom.window.document;
    const toggle = document.querySelector('[data-auto-refresh]') as HTMLInputElement | null;
    toggle!.checked = true;
    toggle!.dispatchEvent(new dom.window.Event('change'));

    await vi.runOnlyPendingTimersAsync();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
