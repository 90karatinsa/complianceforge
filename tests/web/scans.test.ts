// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const TENANT_ID = '55555555-5555-4555-8555-555555555555';

const DEFAULT_SCANS_RESPONSE = {
  data: [
    {
      id: 'scan-failed-001',
      project_id: 'project-001',
      artifact_id: 'artifact-001',
      policy_id: 'policy-001',
      policy_result: 'fail',
      status: 'failed',
      findings: {
        project_name: 'Core API',
        started_by: 'Jenkins',
        feed_version: 'feed-2024.07.01',
        queue_position: 2
      },
      duration_ms: 310000,
      started_at: '2024-07-02T08:24:00.000Z',
      completed_at: '2024-07-02T08:29:10.000Z',
      created_at: '2024-07-02T08:24:00.000Z',
      links: {
        self: '/v1/scans/scan-failed-001',
        sbom: '/v1/sboms/scan-failed-001',
        vulns: '/v1/vulns?scan_id=scan-failed-001',
        licenses: '/v1/licenses?scan_id=scan-failed-001'
      }
    },
    {
      id: 'scan-passed-002',
      project_id: 'project-002',
      artifact_id: 'artifact-002',
      policy_id: 'policy-002',
      policy_result: 'pass',
      status: 'completed',
      findings: {
        project_name: 'Mobile App',
        triggered_by: 'GitHub Actions',
        feed_version: 'feed-2024.06.28'
      },
      duration_ms: 180000,
      started_at: '2024-07-02T09:12:00.000Z',
      completed_at: '2024-07-02T09:15:00.000Z',
      created_at: '2024-07-02T09:12:00.000Z',
      links: {
        self: '/v1/scans/scan-passed-002',
        sbom: '/v1/sboms/scan-passed-002',
        vulns: '/v1/vulns?scan_id=scan-passed-002',
        licenses: '/v1/licenses?scan_id=scan-passed-002'
      }
    },
    {
      id: 'scan-running-003',
      project_id: 'project-003',
      artifact_id: 'artifact-003',
      policy_id: 'policy-003',
      policy_result: 'pass',
      status: 'running',
      findings: {
        project_name: 'CLI Tooling',
        initiator: 'GitLab CI',
        feed_version: 'feed-2024.06.28',
        queue: { position: 1 }
      },
      duration_ms: null,
      started_at: '2024-07-02T08:55:00.000Z',
      completed_at: null,
      created_at: '2024-07-02T08:55:00.000Z',
      links: {
        self: '/v1/scans/scan-running-003',
        sbom: '/v1/sboms/scan-running-003',
        vulns: '/v1/vulns?scan_id=scan-running-003',
        licenses: '/v1/licenses?scan_id=scan-running-003'
      }
    }
  ],
  pagination: { page: 1, page_size: 20, count: 3, total: 40 }
};

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

type ScansResponse = typeof DEFAULT_SCANS_RESPONSE | Response | { status?: number; body?: unknown };

const normalizeScansResponse = (value: ScansResponse) => {
  if (value instanceof Response) {
    return value;
  }

  if (value && typeof value === 'object' && 'data' in value && !('body' in value)) {
    return createJsonResponse(value, 200);
  }

  const status = value?.status ?? 200;
  if (Object.prototype.hasOwnProperty.call(value ?? {}, 'body')) {
    return createJsonResponse(value?.body, status);
  }

  return new Response(null, { status });
};

const flushAsync = async (window: Window) => {
  await Promise.resolve();
  await Promise.resolve();
};

type FetchOverride = (request: {
  url: URL;
  method: string;
  init?: RequestInit;
}) => Promise<ScansResponse | undefined> | ScansResponse | undefined;

async function loadScansPage(options: {
  scansResponses?: Record<string, ScansResponse>;
  fetchOverrides?: FetchOverride[];
} = {}) {
  const responses = options.scansResponses ?? { '1': DEFAULT_SCANS_RESPONSE };
  const overrides = options.fetchOverrides ?? [];

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : String(input);
    const url = new URL(target, 'https://atlas.local');
    const method = (init?.method ?? 'GET').toUpperCase();

    for (const override of overrides) {
      const result = await override({ url, method, init });
      if (result) {
        return normalizeScansResponse(result);
      }
    }

    if (url.pathname === '/v1/scans' && method === 'GET') {
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
      expect(url.searchParams.get('page_size')).toBe('20');
      const response = normalizeScansResponse(responses[url.searchParams.get('page') ?? '1'] ?? responses['1']);
      return response;
    }

    throw new Error(`Unhandled request: ${method} ${url}`);
  });

  const dom = loadPage('scans.html', { fetchImplementation: fetchMock });
  const { window } = dom;

  await new Promise<void>((resolve) => {
    const checkReady = () => {
      const hasRows = window.document.querySelector('tbody[data-scan-body] tr[data-scan-row]');
      const errorState =
        window.document.querySelector('[data-scan-status]')?.getAttribute('data-state') === 'error';
      if (hasRows || errorState) {
        resolve();
        return true;
      }
      return false;
    };

    if (checkReady()) {
      return;
    }

    const handler = () => {
      if (checkReady()) {
        window.document.removeEventListener('scans:data-loaded', handler as EventListener);
      }
    };

    window.document.addEventListener('scans:data-loaded', handler as EventListener);
    queueMicrotask(() => {
      if (checkReady()) {
        window.document.removeEventListener('scans:data-loaded', handler as EventListener);
      }
    });
  });

  await flushAsync(window);

  return { window, fetchMock } as const;
}

describe('scans page', () => {
  it('includes skip link, main landmark, and theme toggle', async () => {
    const { window, fetchMock } = await loadScansPage({
      scansResponses: { '1': DEFAULT_SCANS_RESPONSE }
    });
    const { document } = window;
    const skipLink = document.querySelector('a.skip-link');
    expect(skipLink).not.toBeNull();
    expect(skipLink?.getAttribute('href')).toBe('#main-content');

    const main = document.getElementById('main-content');
    expect(main).not.toBeNull();

    const navElements = Array.from(document.querySelectorAll<HTMLAnchorElement>('header nav a'));
    const navLinks = navElements.map((anchor) => anchor.getAttribute('href'));
    expect(navLinks).toEqual([
      'dashboard.html',
      'projects.html',
      'scans.html',
      'findings.html',
      'legal-review.html',
      'policies.html',
      'exceptions.html',
      'notice-builder.html',
      'feeds.html',
      'reports.html',
      'audit-log.html',
      'integrations.html',
      'health.html',
      'settings.html'
    ]);
    expect(navElements[2]?.getAttribute('aria-current')).toBe('page');

    const toggle = document.querySelector('[data-theme-toggle]');
    expect(toggle).not.toBeNull();
    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    const styleContent = document.querySelector('style')?.textContent ?? '';
    expect(styleContent).toContain(":root[data-theme='contrast']");
    expect(styleContent).toContain('prefers-reduced-motion');
    expect(fetchMock).toHaveBeenCalled();
  });

  it('lists scans with status badges, queue hints, and feed versions', async () => {
    const { window } = await loadScansPage();
    const { document } = window;
    const table = document.querySelector('table[data-table="scan-list"]');
    expect(table).not.toBeNull();
    expect(table?.querySelector('caption')?.textContent).toContain('tarama');
    const rows = table!.querySelectorAll<HTMLTableRowElement>('tbody tr[data-scan-row]');
    expect(rows).toHaveLength(3);

    const [failedRow, passedRow, runningRow] = Array.from(rows);

    const failedBadge = failedRow.querySelector('.status-badge');
    expect(failedBadge?.getAttribute('data-status')).toBe('failed');
    expect(failedRow.querySelector('.queue-meta')?.textContent).toContain('Kuyruk pozisyonu');

    const passedBadge = passedRow.querySelector('.status-badge');
    expect(passedBadge?.getAttribute('data-status')).toBe('completed');

    const runningBadge = runningRow.querySelector('.status-badge');
    expect(runningBadge?.getAttribute('data-status')).toBe('running');

    rows.forEach((row) => {
      const feedVersion = row.querySelector('.feed-version');
      expect(feedVersion?.textContent).toMatch(/feed-/);
    });
  });

  it('provides actions for reports and evidence packs', async () => {
    const { window } = await loadScansPage();
    const { document } = window;
    const links = Array.from(document.querySelectorAll<HTMLAnchorElement>('.actions a'));
    expect(links.map((link) => link.dataset.action)).toEqual(
      expect.arrayContaining(['view-report', 'download-evidence'])
    );

    links.forEach((link) => {
      expect(link.getAttribute('aria-label')).toMatch(/taramasının/);
      const describedBy = link.getAttribute('aria-describedby');
      expect(describedBy).toBeTruthy();
      if (describedBy) {
        const describedElement = document.getElementById(describedBy);
        expect(describedElement?.classList.contains('feed-version')).toBe(true);
      }

      if (link.dataset.action === 'view-report') {
        expect(link.getAttribute('href')).toMatch(/\/v1\/scans\//);
      }

      if (link.dataset.action === 'download-evidence') {
        expect(link.getAttribute('href')).toMatch(/\/evidence-pack$/);
      }
    });
  });

  it('shows pagination cues with accessible labelling', async () => {
    const { window } = await loadScansPage();
    const { document } = window;
    const pagination = document.querySelector('nav[aria-label="Sayfalama"]');
    expect(pagination).not.toBeNull();
    const indicator = pagination?.querySelector('[data-page-indicator]');
    expect(indicator?.textContent).toMatch(/1 \/ 2/);
    const buttons = pagination?.querySelectorAll('button');
    expect(buttons).toHaveLength(2);
    buttons?.forEach((button) => {
      expect(button.querySelector('.sr-only')).not.toBeNull();
    });
  });

  it('filters scans by status and updates summary text', async () => {
    const { window } = await loadScansPage();
    const { document } = window;
    const runningButton = document.querySelector<HTMLButtonElement>('[data-filter="running"]');
    expect(runningButton).not.toBeNull();

    runningButton?.click();
    await flushAsync(window);

    const rows = Array.from(document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-scan-row]'));
    const visibleRows = rows.filter((row) => !row.hasAttribute('hidden'));
    expect(visibleRows).toHaveLength(1);
    expect(visibleRows[0]?.querySelector('.status-badge')?.getAttribute('data-status')).toBe('running');

    expect(runningButton?.getAttribute('aria-pressed')).toBe('true');
    const summary = document.querySelector('[data-filter-status]');
    expect(summary?.textContent).toContain('Çalışan');

    const resetButton = document.querySelector<HTMLButtonElement>('[data-filter="all"]');
    resetButton?.click();
    await flushAsync(window);
    expect(document.querySelectorAll('tbody tr[data-scan-row][hidden]')).toHaveLength(0);
  });

  it('supports toolbar roving focus with arrow keys', async () => {
    const { window } = await loadScansPage();
    const { document } = window;
    const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-filter]'));
    expect(buttons.length).toBeGreaterThanOrEqual(3);

    const allButton = buttons[0];
    const completedButton = buttons[1];
    const lastButton = buttons[buttons.length - 1];

    allButton.focus();
    allButton.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    expect(document.activeElement).toBe(completedButton);
    expect(completedButton.getAttribute('aria-pressed')).toBe('true');

    completedButton.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    expect(document.activeElement).toBe(lastButton);
    expect(lastButton.getAttribute('aria-pressed')).toBe('true');

    lastButton.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }));
    const penultimate = buttons[buttons.length - 2];
    expect(document.activeElement).toBe(penultimate);
    expect(penultimate.getAttribute('aria-pressed')).toBe('true');
  });

  it('requests new pages when pagination buttons are activated', async () => {
    const secondPage = {
      data: [
        {
          ...DEFAULT_SCANS_RESPONSE.data[0],
          id: 'scan-second-004',
          findings: {
            ...DEFAULT_SCANS_RESPONSE.data[0].findings,
            project_name: 'Service API',
            feed_version: 'feed-2024.07.02'
          },
          links: {
            self: '/v1/scans/scan-second-004',
            sbom: '/v1/sboms/scan-second-004',
            vulns: '/v1/vulns?scan_id=scan-second-004',
            licenses: '/v1/licenses?scan_id=scan-second-004'
          }
        }
      ],
      pagination: { page: 2, page_size: 20, count: 1, total: 40 }
    } satisfies typeof DEFAULT_SCANS_RESPONSE;

    const { window, fetchMock } = await loadScansPage({
      scansResponses: { '1': DEFAULT_SCANS_RESPONSE, '2': secondPage }
    });
    const { document } = window;
    const nextButton = document.querySelector<HTMLButtonElement>('button[data-page="next"]');
    expect(nextButton).not.toBeNull();

    const loadPromise = new Promise<void>((resolve) => {
      const handler = () => {
        resolve();
        document.removeEventListener('scans:data-loaded', handler as EventListener);
      };
      document.addEventListener('scans:data-loaded', handler as EventListener);
    });

    nextButton?.click();

    await loadPromise;

    await flushAsync(window);

    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/v1/scans'), expect.anything());
    const rows = document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-scan-row]');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.textContent).toContain('Service API');
  });

  it('exposes auto refresh controls with accessible messaging', async () => {
    const { window } = await loadScansPage();
    const { document } = window;
    const toggle = document.querySelector<HTMLButtonElement>('[data-refresh-toggle]');
    const status = document.querySelector('[data-refresh-status]');

    expect(toggle).not.toBeNull();
    expect(toggle?.getAttribute('aria-pressed')).toBe('true');
    expect(toggle?.textContent ?? '').toContain('durdur');
    expect(status?.textContent ?? '').toContain('Otomatik yenileme açık');

    toggle?.click();
    await flushAsync(window);

    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    expect(toggle?.textContent ?? '').toContain('başlat');
    expect(status?.textContent ?? '').toContain('duraklatıldı');
  });

  it('auto refreshes the scan list when enabled', async () => {
    vi.useFakeTimers();
    try {
      const { window, fetchMock } = await loadScansPage();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(30000);
      await flushAsync(window);

      expect(fetchMock.mock.calls.filter(([, init]) => (init?.method ?? 'GET').toUpperCase() === 'GET')).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('pauses and resumes refresh scheduling via the toggle', async () => {
    vi.useFakeTimers();
    try {
      const { window, fetchMock } = await loadScansPage();
      fetchMock.mockClear();
      const toggle = window.document.querySelector<HTMLButtonElement>('[data-refresh-toggle]');

      toggle?.click();
      await flushAsync(window);
      await vi.advanceTimersByTimeAsync(60000);
      await flushAsync(window);
      expect(fetchMock).not.toHaveBeenCalled();

      toggle?.click();
      await flushAsync(window);
      await vi.advanceTimersByTimeAsync(30000);
      await flushAsync(window);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('aborts an in-flight request when a new load starts', async () => {
    vi.useFakeTimers();
    const abortSpy = vi.fn();
    let requestCount = 0;
    const override: FetchOverride = ({ url, method, init }) => {
      if (url.pathname === '/v1/scans' && method === 'GET') {
        const page = url.searchParams.get('page') ?? '1';
        if (page === '1') {
          requestCount += 1;
          if (requestCount === 1) {
            return undefined;
          }

          return new Promise((_, reject) => {
            const signal = init?.signal as AbortSignal | undefined;
            const abortHandler = () => {
              abortSpy();
              reject(new DOMException('Aborted', 'AbortError'));
            };

            if (signal?.aborted) {
              abortHandler();
              return;
            }

            signal?.addEventListener('abort', abortHandler, { once: true });
          });
        }

        if (page === '2') {
          return createJsonResponse({
            data: [
              {
                ...DEFAULT_SCANS_RESPONSE.data[0],
                id: 'scan-page-2',
                findings: {
                  ...DEFAULT_SCANS_RESPONSE.data[0].findings,
                  project_name: 'Yeni Proje'
                }
              }
            ],
            pagination: { page: 2, page_size: 20, count: 1, total: 40 }
          });
        }
      }

      return undefined;
    };

    try {
      const { window } = await loadScansPage({
        scansResponses: { '1': DEFAULT_SCANS_RESPONSE },
        fetchOverrides: [override]
      });
      const { document } = window;

      await vi.advanceTimersByTimeAsync(30000);
      await flushAsync(window);

      const nextButton = document.querySelector<HTMLButtonElement>('button[data-page="next"]');
      expect(nextButton).not.toBeNull();

      const loadPromise = new Promise<void>((resolve) => {
        const handler = () => {
          resolve();
          document.removeEventListener('scans:data-loaded', handler as EventListener);
        };
        document.addEventListener('scans:data-loaded', handler as EventListener);
      });

      nextButton?.click();

      await loadPromise;
      await flushAsync(window);

      expect(abortSpy).toHaveBeenCalledTimes(1);
      const rows = document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-scan-row]');
      expect(rows).toHaveLength(1);
      expect(rows[0]?.textContent ?? '').toContain('Yeni Proje');
    } finally {
      vi.useRealTimers();
    }
  });
});
