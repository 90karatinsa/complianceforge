// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const TENANT_ID = '55555555-5555-4555-8555-555555555555';

const DEFAULT_LEGAL_FINDINGS_RESPONSE = {
  data: [
    {
      id: 'legal-001',
      tenant_id: TENANT_ID,
      license_id: 'license-001',
      vuln_id: null,
      scan_id: 'scan-001',
      status: 'pending',
      obligations: {
        license: 'GPL-3.0-only',
        severity: 'high',
        license_category: 'copyleft',
        component: 'web-widget@1.2.0',
        vex_state: 'not-affected',
        vex_label: 'Not Affected'
      },
      notes: 'NOTICE güncellemesi gerektiriyor.',
      created_at: '2024-07-01T10:00:00.000Z',
      decision: null,
      decided_at: null,
      rationale: null
    }
  ],
  pagination: { page: 1, page_size: 50 }
};

const DEFAULT_VULNS_RESPONSE = {
  data: [
    {
      id: 'vuln-001',
      scan_id: 'scan-001',
      component_purl: 'pkg:npm/core-lib@2.4.0',
      source: 'OSV',
      cve_id: 'CVE-2024-12345',
      severity: 'critical',
      cvss: 9.8,
      summary: 'Fail-build kapısı bloklu.',
      fixed_version: null,
      detected_at: '2024-07-02T11:00:00.000Z'
    },
    {
      id: 'vuln-002',
      scan_id: 'scan-001',
      component_purl: 'pkg:gem/cli-agent@0.9.1',
      source: 'VEX',
      cve_id: 'CVE-2024-54321',
      severity: 'medium',
      cvss: 5.4,
      summary: 'Policy istisnası 3 gün içinde sona erecek.',
      fixed_version: null,
      detected_at: '2024-07-02T11:30:00.000Z'
    }
  ],
  pagination: { page: 1, page_size: 50, count: 2 }
};

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

type ApiResponse =
  | typeof DEFAULT_LEGAL_FINDINGS_RESPONSE
  | typeof DEFAULT_VULNS_RESPONSE
  | Response
  | { status?: number; body?: unknown };

const normalizeResponse = (value: ApiResponse) => {
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

const waitForNextDataLoaded = (document: Document) =>
  new Promise<void>((resolve) => {
    const handler = () => {
      document.removeEventListener('findings:data-loaded', handler as EventListener);
      resolve();
    };

    document.addEventListener('findings:data-loaded', handler as EventListener, { once: true });
  });

type FetchOverride = (request: {
  url: URL;
  method: string;
  init?: RequestInit;
}) => Promise<ApiResponse | Response | undefined> | ApiResponse | Response | undefined;

async function loadFindingsPage(options: {
  legalResponse?: ApiResponse;
  vulnsResponse?: ApiResponse;
  fetchOverrides?: FetchOverride[];
} = {}) {
  const legalResponse = options.legalResponse ?? DEFAULT_LEGAL_FINDINGS_RESPONSE;
  const vulnsResponse = options.vulnsResponse ?? DEFAULT_VULNS_RESPONSE;
  const overrides = options.fetchOverrides ?? [];

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : String(input);
    const url = new URL(target, 'https://atlas.local');
    const method = (init?.method ?? 'GET').toUpperCase();

    if (method !== 'GET') {
      for (const override of overrides) {
        const result = await override({ url, method, init });
        if (result) {
          return normalizeResponse(result);
        }
      }
    }

    if (url.pathname === '/v1/legal/findings' && method === 'GET') {
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
      expect(url.searchParams.get('status')).toBe('pending');
      return normalizeResponse(legalResponse);
    }

    if (url.pathname === '/v1/vulns' && method === 'GET') {
      expect(url.searchParams.get('page_size')).toBe('50');
      return normalizeResponse(vulnsResponse);
    }

    throw new Error(`Unhandled request: ${method} ${url}`);
  });

  const dom = loadPage('findings.html', { fetchImplementation: fetchMock });
  const { window } = dom;

  await new Promise<void>((resolve) => {
    const checkReady = () => {
      const hasRows = window.document.querySelector('tbody[data-findings-body] tr[data-finding-row]');
      const errorState =
        window.document.querySelector('[data-findings-status]')?.getAttribute('data-state') === 'error';
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
        window.document.removeEventListener('findings:data-loaded', handler as EventListener);
      }
    };

    window.document.addEventListener('findings:data-loaded', handler as EventListener);
    queueMicrotask(() => {
      if (checkReady()) {
        window.document.removeEventListener('findings:data-loaded', handler as EventListener);
      }
    });
  });

  await flushAsync(window);

  return { window, fetchMock } as const;
}

describe('findings page', () => {
  it('exposes skip link, theme toggle, and live bulk summary regions', async () => {
    const { window, fetchMock } = await loadFindingsPage();
    const { document } = window;
    const skipLink = document.querySelector('a.skip-link');
    expect(skipLink).not.toBeNull();
    expect(skipLink?.getAttribute('href')).toBe('#main-content');

    const toggle = document.querySelector('[data-theme-toggle]');
    expect(toggle).not.toBeNull();
    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    const styleContent = document.querySelector('style')?.textContent ?? '';
    expect(styleContent).toContain(":root[data-theme='contrast']");
    expect(styleContent).toContain('prefers-reduced-motion');

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
    expect(navElements[3]?.getAttribute('aria-current')).toBe('page');

    const summary = document.querySelector('[data-bulk-summary]');
    expect(summary?.getAttribute('aria-live')).toBe('polite');
    const count = summary?.querySelector('[data-selected-count]');
    expect(count?.textContent).toBe('0');
    expect(fetchMock).toHaveBeenCalled();
  });

  it('includes filters for search, type, severity, and license', async () => {
    const { window } = await loadFindingsPage();
    const { document } = window;
    const filterIds = ['search', 'type', 'severity', 'license'];
    filterIds.forEach((key) => {
      const control = document.querySelector(`[data-filter="${key}"]`);
      expect(control).not.toBeNull();
    });

    const caption = document.querySelector('table caption');
    expect(caption?.textContent).toContain('Bulgu türü');
  });

  it('supports bulk actions with accessible buttons and feedback', async () => {
    const { window } = await loadFindingsPage();
    const { document } = window;
    const bulkButtons = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-bulk]')).map((btn) =>
      btn.getAttribute('data-bulk')
    );
    expect(bulkButtons).toEqual(expect.arrayContaining(['assign', 'mark-allow', 'mark-deny', 'send-legal']));

    const feedback = document.querySelector('[data-bulk-feedback]');
    expect(feedback?.getAttribute('role')).toBe('status');
    expect(feedback?.getAttribute('aria-live')).toBe('assertive');
  });

  it('marks each finding row with VEX badges or severity labels', async () => {
    const { window } = await loadFindingsPage();
    const { document } = window;
    const rows = document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]');
    expect(rows.length).toBeGreaterThanOrEqual(3);
    rows.forEach((row) => {
      expect(row.getAttribute('tabindex')).toBe('0');
      const badge = row.querySelector('.vex-badge');
      const severity = row.querySelector('.severity');
      const actionsCell = row.querySelector('[data-actions="vex"]');
      expect(actionsCell).not.toBeNull();
      expect(badge || severity).not.toBeNull();
      if (severity) {
        expect(severity.querySelector('.sr-only')).not.toBeNull();
        expect(severity.querySelector('[aria-hidden="true"]')).not.toBeNull();
      }
      if (badge) {
        expect(badge.getAttribute('aria-label') ?? '').toMatch(/VEX durumu/);
        expect(badge.getAttribute('title') ?? '').toMatch(/VEX durumu/);
      }
    });
  });
});

describe('findings page interactions', () => {
  it('filters findings with combined controls and polite feedback', async () => {
    const { window } = await loadFindingsPage();
    const { document } = window;
    const searchInput = document.querySelector<HTMLInputElement>('[data-filter="search"]');
    const typeSelect = document.querySelector<HTMLSelectElement>('[data-filter="type"]');
    const severitySelect = document.querySelector<HTMLSelectElement>('[data-filter="severity"]');
    const licenseSelect = document.querySelector<HTMLSelectElement>('[data-filter="license"]');
    const feedback = document.querySelector('[data-filter-feedback]');

    expect(feedback?.textContent ?? '').toContain('Tüm bulgular');

    if (searchInput) {
      searchInput.value = 'cli';
      searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    await flushAsync(window);

    let visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(1);
    expect(feedback?.textContent ?? '').toContain('Arama "cli"');

    if (searchInput) {
      searchInput.value = '';
      searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    if (typeSelect) {
      typeSelect.value = 'license';
      typeSelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    await flushAsync(window);

    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(1);
    expect(visibleRows[0]?.textContent ?? '').toContain('GPL-3.0-only');
    expect(feedback?.textContent ?? '').toMatch(/Lisans/i);
    Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row][hidden]')).forEach((row) => {
      expect(row.getAttribute('tabindex')).toBe('-1');
    });

    if (severitySelect) {
      severitySelect.value = 'medium';
      severitySelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    await flushAsync(window);

    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(0);
    expect(feedback?.textContent ?? '').toContain('bulunamadı');

    if (severitySelect) {
      severitySelect.value = 'all';
      severitySelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    if (licenseSelect) {
      licenseSelect.value = 'copyleft';
      licenseSelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    await flushAsync(window);

    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(1);
    expect(feedback?.textContent ?? '').toContain('Copyleft');

    const checkbox = visibleRows[0]?.querySelector<HTMLInputElement>('[data-select]');
    checkbox?.click();
    const selectedCount = document.querySelector('[data-selected-count]');
    expect(selectedCount?.textContent).toBe('1');

    if (licenseSelect) {
      licenseSelect.value = 'permissive';
      licenseSelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    if (typeSelect) {
      typeSelect.value = 'all';
      typeSelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    await flushAsync(window);

    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(2);
    expect(selectedCount?.textContent).toBe('1');
  });

  it('tracks bulk selections and updates feedback', async () => {
    const { window } = await loadFindingsPage();
    const { document } = window;
    const checkboxes = Array.from(document.querySelectorAll<HTMLInputElement>('[data-select]'));
    expect(checkboxes.length).toBeGreaterThan(0);

    const bulkButtons = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-bulk]'));
    bulkButtons.forEach((button) => {
      expect(button.disabled).toBe(true);
    });

    const firstCheckbox = checkboxes[0];
    firstCheckbox.click();

    const selectedCount = document.querySelector('[data-selected-count]');
    expect(selectedCount?.textContent).toBe('1');

    bulkButtons.forEach((button) => {
      expect(button.disabled).toBe(false);
    });

    const feedback = document.querySelector('[data-bulk-feedback]');
    const allowButton = document.querySelector<HTMLButtonElement>('[data-bulk="mark-allow"]');
    allowButton?.click();
    expect(feedback?.textContent).toContain('Allow');

    firstCheckbox.click();
    expect(selectedCount?.textContent).toBe('0');
    expect(feedback?.textContent).toContain('Henüz işlem yapılmadı');
  });

  it('allows analysts to create a VEX statement from the findings table', async () => {
    const vexPostOverride = vi.fn(async ({ url, method, init }) => {
      if (url.pathname === '/v1/vex' && method === 'POST') {
        const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
        expect(payload).toMatchObject({
          tenant_id: TENANT_ID,
          component_purl: 'pkg:npm/core-lib@2.4.0',
          status: 'not_affected'
        });
        expect(payload.justification).toBe('Paket kullanılmıyor');
        return createJsonResponse(
          {
            data: {
              id: 'vex-new',
              status: 'not_affected',
              component_purl: payload.component_purl,
              advisory_id: payload.advisory_id ?? null,
              justification: payload.justification ?? null
            }
          },
          201
        );
      }

      return undefined;
    });

    const { window, fetchMock } = await loadFindingsPage({ fetchOverrides: [vexPostOverride] });
    const { document } = window;
    const targetRow = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')).find(
      (row) => row.textContent?.includes('core-lib')
    );
    expect(targetRow).toBeTruthy();

    const actionButton = targetRow?.querySelector<HTMLButtonElement>('[data-actions="vex"] button');
    expect(actionButton?.textContent ?? '').toContain('VEX durumu ekle');
    actionButton?.click();

    await flushAsync(window);

    expect(document.querySelector('[data-vex-dialog]')?.getAttribute('hidden')).toBeNull();

    const justification = document.querySelector<HTMLTextAreaElement>('[data-vex-justification]');
    if (justification) {
      justification.value = 'Paket kullanılmıyor';
      justification.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const refreshPromise = waitForNextDataLoaded(document);
    document.querySelector<HTMLButtonElement>('[data-vex-submit]')?.click();

    await refreshPromise;
    await flushAsync(window);

    expect(vexPostOverride).toHaveBeenCalledTimes(1);
    const postCalls = fetchMock.mock.calls.filter(([, init]) => (init?.method ?? 'GET').toUpperCase() === 'POST');
    expect(postCalls).toHaveLength(1);

    const refreshedRow = Array.from(
      document.querySelectorAll<HTMLTableRowElement>('[data-finding-row]')
    ).find((row) => row.textContent?.includes('core-lib'));
    const badge = refreshedRow?.querySelector('.vex-badge');
    expect(badge?.textContent ?? '').toContain('Not Affected');
    expect(badge?.getAttribute('data-state')).toBe('not-affected');
    expect(document.querySelector('[data-vex-dialog]')?.getAttribute('hidden')).toBe('');
    expect(
      refreshedRow?.querySelector<HTMLButtonElement>('[data-actions="vex"] button')?.textContent ?? ''
    ).toContain('güncelle');
  });

  it('updates an existing VEX statement via PUT and refreshes the badge', async () => {
    const vexUpdateOverride = vi.fn(async ({ url, method, init }) => {
      if (url.pathname === '/v1/vex/vex-existing' && method === 'PUT') {
        const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
        expect(payload).toMatchObject({
          tenant_id: TENANT_ID,
          status: 'fixed',
          component_purl: 'pkg:npm/core-lib@2.4.0'
        });
        expect(payload.justification).toBe('Yama yayınlandı');
        return createJsonResponse({
          data: {
            id: 'vex-existing',
            status: 'fixed',
            component_purl: payload.component_purl,
            advisory_id: payload.advisory_id ?? null,
            justification: payload.justification ?? null
          }
        });
      }

      return undefined;
    });

    const vulnsResponse = {
      ...DEFAULT_VULNS_RESPONSE,
      data: [
        {
          ...DEFAULT_VULNS_RESPONSE.data[0],
          vex_state: 'not-affected',
          vex_statement_id: 'vex-existing',
          vex_justification: 'Başlangıç yorumu',
          permissions: ['vex:write']
        }
      ]
    } satisfies typeof DEFAULT_VULNS_RESPONSE;

    const { window } = await loadFindingsPage({
      vulnsResponse,
      fetchOverrides: [vexUpdateOverride]
    });

    const { document } = window;
    const initialRow = document.querySelector<HTMLTableRowElement>('[data-finding-row]');
    expect(initialRow?.querySelector('.vex-badge')?.getAttribute('data-state')).toBe('not-affected');

    const actionButton = initialRow?.querySelector<HTMLButtonElement>('[data-actions="vex"] button');
    actionButton?.click();
    await flushAsync(window);

    const fixedRadio = document.querySelector<HTMLInputElement>('input[name="vex-status"][value="fixed"]');
    fixedRadio?.click();

    const justification = document.querySelector<HTMLTextAreaElement>('[data-vex-justification]');
    if (justification) {
      justification.value = 'Yama yayınlandı';
      justification.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const refreshPromise = waitForNextDataLoaded(document);
    document.querySelector<HTMLButtonElement>('[data-vex-submit]')?.click();
    await refreshPromise;
    await flushAsync(window);

    expect(vexUpdateOverride).toHaveBeenCalledTimes(1);

    const refreshedRow = document.querySelector<HTMLTableRowElement>('[data-finding-row]');
    const afterPutBadge = refreshedRow?.querySelector('.vex-badge');
    expect(afterPutBadge?.getAttribute('data-state')).toBe('fixed');
    expect(
      refreshedRow?.querySelector<HTMLButtonElement>('[data-actions="vex"] button')?.textContent ?? ''
    ).toContain('güncelle');
  });

  it('revokes an existing VEX statement and restores the row state', async () => {
    const vexDeleteOverride = vi.fn(async ({ url, method, init }) => {
      if (url.pathname === '/v1/vex/vex-existing' && method === 'DELETE') {
        const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
        expect(payload).toMatchObject({ tenant_id: TENANT_ID });
        return new Response(null, { status: 204 });
      }

      return undefined;
    });

    const vulnsResponse = {
      ...DEFAULT_VULNS_RESPONSE,
      data: [
        {
          ...DEFAULT_VULNS_RESPONSE.data[0],
          vex_state: 'not-affected',
          vex_statement_id: 'vex-existing',
          permissions: ['vex:write']
        }
      ]
    } satisfies typeof DEFAULT_VULNS_RESPONSE;

    const { window } = await loadFindingsPage({
      vulnsResponse,
      fetchOverrides: [vexDeleteOverride]
    });

    const { document } = window;
    const row = document.querySelector<HTMLTableRowElement>('[data-finding-row]');
    expect(row?.querySelector('.vex-badge')).not.toBeNull();

    row?.querySelector<HTMLButtonElement>('[data-actions="vex"] button')?.click();
    await flushAsync(window);

    const revokeButton = document.querySelector<HTMLButtonElement>('[data-vex-revoke]');
    expect(revokeButton?.hidden).toBe(false);
    const refreshPromise = waitForNextDataLoaded(document);
    revokeButton?.click();

    await refreshPromise;
    await flushAsync(window);

    expect(vexDeleteOverride).toHaveBeenCalledTimes(1);

    const refreshedRow = document.querySelector<HTMLTableRowElement>('[data-finding-row]');
    const afterDeleteBadge = refreshedRow?.querySelector('.vex-badge');
    expect(afterDeleteBadge).toBeNull();
    expect(
      refreshedRow?.querySelector<HTMLButtonElement>('[data-actions="vex"] button')?.textContent ?? ''
    ).toContain('VEX durumu ekle');
    expect(document.querySelector('[data-vex-dialog]')?.getAttribute('hidden')).toBe('');
  });
});
