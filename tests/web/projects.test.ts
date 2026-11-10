// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const TENANT_ID = '55555555-5555-4555-8555-555555555555';

const DEFAULT_PROJECTS_RESPONSE = {
  data: [
    {
      id: '11111111-1111-4111-8111-111111111111',
      tenant_id: TENANT_ID,
      name: 'Core API',
      description: null,
      repo_url: 'https://git.example.com/core.git',
      oci_ref: null,
      metadata: {
        owner: 'core',
        owner_label: 'Core Platform',
        risk_level: 'critical',
        last_scan_completed_at: '2024-07-01T12:30:00.000Z',
        policy_status_label: 'Fail-build (Lisans)'
      }
    },
    {
      id: '22222222-2222-4222-8222-222222222222',
      tenant_id: TENANT_ID,
      name: 'Mobile App',
      description: null,
      repo_url: 'https://git.example.com/mobile.git',
      oci_ref: null,
      metadata: {
        owner: 'mobile',
        owner_label: 'Mobile',
        risk_level: 'high',
        last_scan_completed_at: '2024-06-30T19:10:00.000Z',
        policy_status_label: 'Hukuk incelemesi bekliyor'
      }
    },
    {
      id: '33333333-3333-4333-8333-333333333333',
      tenant_id: TENANT_ID,
      name: 'CLI Tooling',
      description: null,
      repo_url: 'https://git.example.com/cli.git',
      oci_ref: null,
      metadata: {
        owner: 'embedded',
        owner_label: 'Embedded',
        risk_level: 'medium',
        last_scan_completed_at: '2024-06-28T08:20:00.000Z',
        policy_status_label: 'NOTICE güncellemesi gerektiriyor'
      }
    }
  ],
  pagination: { page: 1, page_size: 50, count: 3 }
};

type ProjectRecord = (typeof DEFAULT_PROJECTS_RESPONSE.data)[number];
type ProjectDetailPayload = { data: ProjectRecord };
type ProjectScanRecord = {
  id: string;
  project_id: string;
  status: string;
  policy_result: string;
  findings?: Record<string, unknown>;
  started_at?: string | null;
  completed_at?: string | null;
  created_at?: string | null;
};
type ProjectScansPayload = {
  data: ProjectScanRecord[];
  pagination?: { page: number; page_size: number; count: number };
};

const DEFAULT_PROJECT_DETAIL_RESPONSES: Record<string, ProjectDetailPayload> = Object.fromEntries(
  DEFAULT_PROJECTS_RESPONSE.data.map((project, index) => [
    project.id,
    {
      data: {
        ...project,
        description:
          project.description ??
          (index === 0 ? 'Core API bileşenlerinin tarama sonuçlarını izler.' : null)
      }
    }
  ])
);

const DEFAULT_PROJECT_SCANS_RESPONSE: ProjectScansPayload = {
  data: [
    {
      id: 'scan-core-success',
      project_id: DEFAULT_PROJECTS_RESPONSE.data[0].id,
      status: 'completed',
      policy_result: 'pass',
      findings: {
        feed_version: 'feed-2024.07.01',
        triggered_by: 'GitHub Actions'
      },
      started_at: '2024-07-02T09:00:00.000Z',
      completed_at: '2024-07-02T09:03:00.000Z',
      created_at: '2024-07-02T09:00:00.000Z'
    },
    {
      id: 'scan-core-fail',
      project_id: DEFAULT_PROJECTS_RESPONSE.data[0].id,
      status: 'failed',
      policy_result: 'fail',
      findings: {
        feed_version: 'feed-2024.06.25',
        started_by: 'Jenkins',
        queue_position: 3
      },
      started_at: '2024-06-28T08:10:00.000Z',
      completed_at: '2024-06-28T08:16:30.000Z',
      created_at: '2024-06-28T08:10:00.000Z'
    }
  ],
  pagination: { page: 1, page_size: 5, count: 2 }
};

const DEFAULT_EMPTY_PROJECT_SCANS_RESPONSE: ProjectScansPayload = {
  data: [],
  pagination: { page: 1, page_size: 5, count: 0 }
};

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

const normalizeProjectsResponse = (
  value:
    | typeof DEFAULT_PROJECTS_RESPONSE
    | Response
    | { status?: number; body?: unknown }
) => {
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

type ProjectsResponseConfig = typeof DEFAULT_PROJECTS_RESPONSE | Response | { status?: number; body?: unknown };
type ProjectDetailResponseConfig = ProjectDetailPayload | Response | { status?: number; body?: unknown };
type ProjectScansResponseConfig = ProjectScansPayload | Response | { status?: number; body?: unknown };
type FetchOverrideResult =
  | ProjectsResponseConfig
  | ProjectDetailResponseConfig
  | ProjectScansResponseConfig
  | Response
  | undefined
  | void;
type FetchOverride = (request: { url: URL; method: string; init?: RequestInit }) =>
  | FetchOverrideResult
  | Promise<FetchOverrideResult>;

const normalizeProjectDetailResponse = (value: ProjectDetailResponseConfig) => {
  if (value instanceof Response) {
    return value;
  }

  if (value && typeof value === 'object' && 'data' in value && !('body' in value)) {
    return createJsonResponse(value, 200);
  }

  const status = value?.status ?? 200;
  if (Object.prototype.hasOwnProperty.call(value ?? {}, 'body')) {
    return createJsonResponse((value as { body?: unknown }).body, status);
  }

  return new Response(null, { status });
};

const normalizeProjectScansResponse = (value: ProjectScansResponseConfig) => {
  if (value instanceof Response) {
    return value;
  }

  if (value && typeof value === 'object' && 'data' in value && !('body' in value)) {
    const payload = value.pagination
      ? value
      : { ...value, pagination: { page: 1, page_size: value.data.length || 1, count: value.data.length } };
    return createJsonResponse(payload, 200);
  }

  const status = value?.status ?? 200;
  if (Object.prototype.hasOwnProperty.call(value ?? {}, 'body')) {
    return createJsonResponse((value as { body?: unknown }).body, status);
  }

  return new Response(null, { status });
};

const flushAsync = async (window: Window) => {
  await Promise.resolve();
  await Promise.resolve();
};

const waitForDetailEvent = (
  window: Window,
  expectation: { status?: string; projectId?: string; source?: string } = {}
) =>
  new Promise<void>((resolve) => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent).detail ?? {};
      const matchesStatus = expectation.status === undefined || detail.status === expectation.status;
      const matchesProject = expectation.projectId === undefined || detail.projectId === expectation.projectId;
      const matchesSource = expectation.source === undefined || detail.source === expectation.source;

      if (matchesStatus && matchesProject && matchesSource) {
        window.document.removeEventListener('projects:detail-loaded', handler as EventListener);
        resolve();
      }
    };

    window.document.addEventListener('projects:detail-loaded', handler as EventListener);
  });

const waitForDrawerClose = (window: Window) =>
  new Promise<void>((resolve) => {
    const handler = () => {
      window.document.removeEventListener('projects:detail-closed', handler as EventListener);
      resolve();
    };

    window.document.addEventListener('projects:detail-closed', handler as EventListener);
  });

const getRequestUrl = (value: RequestInfo | URL) => {
  if (typeof value === 'string') {
    return value;
  }

  if (value instanceof URL) {
    return value.toString();
  }

  if (value instanceof Request) {
    return value.url;
  }

  return String(value);
};

async function loadProjectsPage(options: {
  projectsResponse?: ProjectsResponseConfig;
  detailResponses?: Record<string, ProjectDetailResponseConfig>;
  projectScansResponses?: Record<string, ProjectScansResponseConfig>;
  fetchOverride?: FetchOverride;
} = {}) {
  const projectsResponse = options.projectsResponse ?? DEFAULT_PROJECTS_RESPONSE;

  const detailMap = new Map<string, ProjectDetailResponseConfig>(
    Object.entries(DEFAULT_PROJECT_DETAIL_RESPONSES)
  );
  Object.entries(options.detailResponses ?? {}).forEach(([key, value]) => {
    detailMap.set(key, value);
  });

  const scansMap = new Map<string, ProjectScansResponseConfig>(
    DEFAULT_PROJECTS_RESPONSE.data.map((project, index) => [
      project.id,
      index === 0 ? DEFAULT_PROJECT_SCANS_RESPONSE : DEFAULT_EMPTY_PROJECT_SCANS_RESPONSE
    ])
  );
  Object.entries(options.projectScansResponses ?? {}).forEach(([key, value]) => {
    scansMap.set(key, value);
  });

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : String(input);
    const url = new URL(target, 'https://atlas.local');
    const method = (init?.method ?? 'GET').toUpperCase();

    const overrideCandidate = options.fetchOverride
      ? await options.fetchOverride({ url, method, init })
      : undefined;

    if (overrideCandidate !== undefined && overrideCandidate !== null) {
      if (overrideCandidate instanceof Response) {
        return overrideCandidate;
      }

      if (url.pathname === '/v1/projects' && method === 'GET') {
        return normalizeProjectsResponse(overrideCandidate as ProjectsResponseConfig);
      }

      if (url.pathname.startsWith('/v1/projects/') && method === 'GET') {
        return normalizeProjectDetailResponse(overrideCandidate as ProjectDetailResponseConfig);
      }

      if (url.pathname === '/v1/scans' && method === 'GET' && url.searchParams.get('project_id')) {
        return normalizeProjectScansResponse(overrideCandidate as ProjectScansResponseConfig);
      }
    }

    if (url.pathname === '/v1/projects' && method === 'GET') {
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
      return normalizeProjectsResponse(projectsResponse);
    }

    if (url.pathname.startsWith('/v1/projects/') && method === 'GET') {
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
      const projectId = url.pathname.split('/').pop() ?? '';
      const response = detailMap.get(projectId) ?? { status: 404 };
      return normalizeProjectDetailResponse(response);
    }

    if (url.pathname === '/v1/scans' && method === 'GET' && url.searchParams.get('project_id')) {
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
      const projectId = url.searchParams.get('project_id') ?? '';
      const response = scansMap.get(projectId) ?? DEFAULT_EMPTY_PROJECT_SCANS_RESPONSE;
      return normalizeProjectScansResponse(response);
    }

    throw new Error(`Unhandled request: ${method} ${url}`);
  });

  const dom = loadPage('projects.html', { fetchImplementation: fetchMock });
  const { window } = dom;

  await new Promise<void>((resolve) => {
    const checkReady = () => {
      const hasRows = window.document.querySelector('tbody[data-projects-body] tr[data-project-row]');
      const errorState = window.document
        .querySelector('[data-projects-status]')
        ?.getAttribute('data-state') === 'error';
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
        window.document.removeEventListener('projects:data-loaded', handler);
      }
    };

    window.document.addEventListener('projects:data-loaded', handler);
    queueMicrotask(() => {
      if (checkReady()) {
        window.document.removeEventListener('projects:data-loaded', handler);
      }
    });
  });

  await flushAsync(window);

  return { window, fetchMock, projectsResponse } as const;
}

describe('projects page', () => {
  it('exposes skip link, main landmark, and theme toggle', async () => {
    const { window, fetchMock } = await loadProjectsPage();
    const { document } = window;
    const skipLink = document.querySelector('a.skip-link');
    expect(skipLink).not.toBeNull();
    expect(skipLink?.getAttribute('href')).toBe('#main-content');

    const main = document.getElementById('main-content');
    expect(main).not.toBeNull();

    const navElements = Array.from(document.querySelectorAll<HTMLAnchorElement>('header nav a'));
    const navLinks = navElements.map((link) => link.getAttribute('href'));
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
    expect(navElements[1]?.getAttribute('aria-current')).toBe('page');

    const toggle = document.querySelector('[data-theme-toggle]');
    expect(toggle).not.toBeNull();
    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    const styleContent = document.querySelector('style')?.textContent ?? '';
    expect(styleContent).toContain(":root[data-theme='contrast']");
    expect(styleContent).toContain('prefers-reduced-motion');
    expect(fetchMock).toHaveBeenCalled();
  });

  it('offers project search and filter controls', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const searchInput = document.querySelector<HTMLInputElement>('[data-filter="search"]');
    expect(searchInput).not.toBeNull();
    expect(searchInput?.type).toBe('search');
    expect(searchInput?.placeholder).toContain('Proje');

    const riskSelect = document.querySelector<HTMLSelectElement>('[data-filter="risk"]');
    expect(riskSelect).not.toBeNull();
    const options = Array.from(riskSelect!.options).map((opt) => opt.value);
    expect(options).toEqual(['all', 'critical', 'high', 'medium', 'low']);
  });

  it('renders a heatmap with accessible risk cells', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const cells = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-risk-cell]'));
    expect(cells.length).toBeGreaterThanOrEqual(4);
    cells.forEach((cell) => {
      expect(cell.tagName).toBe('BUTTON');
      expect(cell.type).toBe('button');
      expect(cell.getAttribute('data-risk')).toMatch(/critical|high|medium|low/);
      expect(cell.querySelector('strong')).not.toBeNull();
      expect(cell.hasAttribute('role')).toBe(false);
      expect(cell.hasAttribute('tabindex')).toBe(false);
      expect(cell.getAttribute('aria-pressed')).toBe('false');
    });
  });

  it('builds a keyboard-focusable projects table', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const table = document.querySelector('table');
    const caption = table?.querySelector('caption');
    expect(caption?.textContent).toContain('risk seviyesi');
    expect(table?.getAttribute('aria-describedby')).toContain('projects-table-caption');

    const rows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]'));
    expect(rows).toHaveLength(3);
    rows.forEach((row) => {
      expect(row.getAttribute('tabindex')).toBe('0');
      expect(row.getAttribute('role')).toBe('button');
      expect(row.getAttribute('aria-haspopup')).toBe('dialog');
      expect(row.getAttribute('aria-expanded')).toBe('false');
      const cells = row.querySelectorAll('td');
      expect(cells.length).toBe(4);
    });
  });

  it('filters projects when selecting risk heatmap cells', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const criticalCell = document.querySelector<HTMLButtonElement>('[data-risk-cell][data-risk="critical"]');
    expect(criticalCell).not.toBeNull();

    criticalCell?.click();
    expect(criticalCell?.getAttribute('aria-pressed')).toBe('true');
    const riskSelect = document.querySelector<HTMLSelectElement>('[data-filter="risk"]');
    expect(riskSelect?.value).toBe('critical');
    const visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows.length).toBeGreaterThan(0);
    visibleRows.forEach((row) => {
      const riskCell = row.querySelector('[data-risk]');
      expect(riskCell?.getAttribute('data-risk')).toBe('critical');
    });

    const resetButton = document.querySelector<HTMLButtonElement>('[data-risk-reset]');
    resetButton?.click();
    expect(resetButton?.getAttribute('aria-pressed')).toBe('true');
    expect(riskSelect?.value).toBe('all');
    expect(document.querySelectorAll('[data-project-row][hidden]')).toHaveLength(0);
  });

  it('combines search, owner, and risk filters with live feedback', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const searchInput = document.querySelector<HTMLInputElement>('[data-filter="search"]');
    const ownerSelect = document.querySelector<HTMLSelectElement>('[data-filter="owner"]');
    const riskSelect = document.querySelector<HTMLSelectElement>('[data-filter="risk"]');
    const feedback = document.querySelector('[data-risk-feedback]');
    expect(searchInput).not.toBeNull();
    expect(ownerSelect).not.toBeNull();
    expect(riskSelect).not.toBeNull();
    expect(feedback).not.toBeNull();

    if (searchInput) {
      searchInput.value = 'cli';
      searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const riskCells = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-risk-cell]'));
    const countsAfterSearch = Object.fromEntries(
      riskCells.map((cell) => [cell.getAttribute('data-risk'), cell.querySelector('strong')?.textContent?.trim()])
    );
    expect(countsAfterSearch).toMatchObject({ critical: '0', high: '0', medium: '1', low: '0' });
    let visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(1);
    expect(feedback?.textContent ?? '').toContain('Arama "cli"');

    if (searchInput) {
      searchInput.value = '';
      searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    if (ownerSelect) {
      ownerSelect.value = 'mobile';
      ownerSelect.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(1);
    expect(visibleRows[0]?.querySelector('td')?.textContent).toContain('Mobile App');
    expect(feedback?.textContent ?? '').toContain('Mobile');

    const highCell = document.querySelector<HTMLButtonElement>('[data-risk-cell][data-risk="high"]');
    highCell?.click();
    expect(riskSelect?.value).toBe('high');
    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(1);
    expect(feedback?.textContent ?? '').toContain('Yüksek risk');

    highCell?.click();
    expect(riskSelect?.value).toBe('all');

    if (searchInput) {
      searchInput.value = 'zzzzz';
      searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    visibleRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]')).filter(
      (row) => !row.hasAttribute('hidden')
    );
    expect(visibleRows).toHaveLength(0);
    expect(feedback?.textContent).toContain('bulunamadı');
  });

  it('removes hidden project rows from the tab order while filtering', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const searchInput = document.querySelector<HTMLInputElement>('[data-filter="search"]');
    expect(searchInput).not.toBeNull();

    if (!searchInput) {
      return;
    }

    searchInput.value = 'mobile';
    searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));

    const rows = Array.from(document.querySelectorAll<HTMLTableRowElement>('[data-project-row]'));
    const hiddenRows = rows.filter((row) => row.hasAttribute('hidden'));
    const visibleRows = rows.filter((row) => !row.hasAttribute('hidden'));

    hiddenRows.forEach((row) => {
      expect(row.getAttribute('tabindex')).toBe('-1');
    });
    visibleRows.forEach((row) => {
      expect(row.getAttribute('tabindex')).toBe('0');
    });

    searchInput.value = '';
    searchInput.dispatchEvent(new window.Event('input', { bubbles: true }));

    rows.forEach((row) => {
      expect(row.getAttribute('tabindex')).toBe('0');
      expect(row.hasAttribute('hidden')).toBe(false);
    });
  });

  it('keeps heatmap buttons naturally focusable without custom roving logic', async () => {
    const { window } = await loadProjectsPage();
    const { document } = window;
    const cells = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-risk-cell]'));
    expect(cells.length).toBeGreaterThanOrEqual(4);

    cells.forEach((cell) => {
      expect(cell.tabIndex).toBe(0);
      cell.focus();
      expect(document.activeElement).toBe(cell);
    });
  });

  it('opens project detail drawer with fetched data and scans', async () => {
    const projectId = DEFAULT_PROJECTS_RESPONSE.data[0].id;
    const detailResponse: ProjectDetailPayload = {
      data: {
        ...DEFAULT_PROJECTS_RESPONSE.data[0],
        description: 'Core API bileşenlerinin tarama sonuçlarını izler.'
      }
    };
    const scansResponse: ProjectScansPayload = {
      data: [
        {
          id: 'scan-demo-001',
          project_id: projectId,
          status: 'completed',
          policy_result: 'pass',
          findings: { feed_version: 'feed-2024.07.01', triggered_by: 'GitHub Actions' },
          started_at: '2024-07-02T09:00:00.000Z',
          completed_at: '2024-07-02T09:03:00.000Z',
          created_at: '2024-07-02T09:00:00.000Z'
        },
        {
          id: 'scan-demo-002',
          project_id: projectId,
          status: 'failed',
          policy_result: 'fail',
          findings: { feed_version: 'feed-2024.06.25', started_by: 'Jenkins', queue_position: 2 },
          started_at: '2024-06-28T08:15:00.000Z',
          completed_at: '2024-06-28T08:21:00.000Z',
          created_at: '2024-06-28T08:15:00.000Z'
        }
      ],
      pagination: { page: 1, page_size: 5, count: 2 }
    };

    const { window, fetchMock } = await loadProjectsPage({
      detailResponses: { [projectId]: detailResponse },
      projectScansResponses: { [projectId]: scansResponse }
    });
    const { document } = window;
    const row = document.querySelector<HTMLTableRowElement>(
      `[data-project-row][data-project-id="${projectId}"]`
    );
    expect(row).not.toBeNull();

    const detailEvent = waitForDetailEvent(window, {
      status: 'success',
      projectId,
      source: 'network'
    });
    row?.click();
    await detailEvent;
    await flushAsync(window);

    expect(row?.getAttribute('aria-expanded')).toBe('true');

    const drawer = document.querySelector<HTMLElement>('[data-project-drawer]');
    expect(drawer?.hasAttribute('hidden')).toBe(false);

    const content = document.querySelector<HTMLElement>('[data-project-content]');
    const contentText = content?.textContent ?? '';
    expect(contentText).toContain('Core API');
    expect(contentText).toContain('Sorumlu ekip');
    expect(contentText).toContain('Feed sürümü: feed-2024.07.01');
    expect(contentText).toContain('Politika sonucu: Geçti');

    const detailCalls = fetchMock.mock.calls.filter(([input]) =>
      getRequestUrl(input).includes(`/v1/projects/${projectId}`)
    );
    expect(detailCalls).toHaveLength(1);

    const scanCalls = fetchMock.mock.calls.filter(([input]) => {
      const url = getRequestUrl(input);
      return url.startsWith('/v1/scans') && url.includes(`project_id=${projectId}`);
    });
    expect(scanCalls).toHaveLength(1);
  });

  it('caches project detail responses and restores focus when closing drawer', async () => {
    const projectId = DEFAULT_PROJECTS_RESPONSE.data[0].id;
    const { window, fetchMock } = await loadProjectsPage({
      detailResponses: { [projectId]: DEFAULT_PROJECT_DETAIL_RESPONSES[projectId] },
      projectScansResponses: { [projectId]: DEFAULT_PROJECT_SCANS_RESPONSE }
    });
    const { document } = window;
    const row = document.querySelector<HTMLTableRowElement>(
      `[data-project-row][data-project-id="${projectId}"]`
    );
    expect(row).not.toBeNull();

    const networkEvent = waitForDetailEvent(window, {
      status: 'success',
      projectId,
      source: 'network'
    });
    row?.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await networkEvent;
    await flushAsync(window);

    const closeButton = document.querySelector<HTMLButtonElement>('[data-project-close]');
    expect(closeButton).not.toBeNull();
    const closed = waitForDrawerClose(window);
    closeButton?.click();
    await closed;
    await flushAsync(window);

    expect(row?.getAttribute('aria-expanded')).toBe('false');
    expect(window.document.activeElement).toBe(row);

    const detailCallsAfterFirstOpen = fetchMock.mock.calls.filter(([input]) =>
      getRequestUrl(input).includes(`/v1/projects/${projectId}`)
    ).length;
    const scanCallsAfterFirstOpen = fetchMock.mock.calls.filter(([input]) => {
      const url = getRequestUrl(input);
      return url.startsWith('/v1/scans') && url.includes(`project_id=${projectId}`);
    }).length;

    const cacheEvent = waitForDetailEvent(window, {
      status: 'success',
      projectId,
      source: 'cache'
    });
    row?.click();
    await cacheEvent;
    await flushAsync(window);

    expect(
      fetchMock.mock.calls.filter(([input]) =>
        getRequestUrl(input).includes(`/v1/projects/${projectId}`)
      ).length
    ).toBe(detailCallsAfterFirstOpen);

    expect(
      fetchMock.mock.calls.filter(([input]) => {
        const url = getRequestUrl(input);
        return url.startsWith('/v1/scans') && url.includes(`project_id=${projectId}`);
      }).length
    ).toBe(scanCallsAfterFirstOpen);

    const drawer = document.querySelector<HTMLElement>('[data-project-drawer]');
    expect(drawer?.hasAttribute('hidden')).toBe(false);
  });

  it('surfaces an error message when project detail fetch fails', async () => {
    const projectId = DEFAULT_PROJECTS_RESPONSE.data[0].id;
    const { window, fetchMock } = await loadProjectsPage({
      detailResponses: { [projectId]: { status: 500 } },
      projectScansResponses: { [projectId]: DEFAULT_PROJECT_SCANS_RESPONSE }
    });
    const { document } = window;
    const row = document.querySelector<HTMLTableRowElement>(
      `[data-project-row][data-project-id="${projectId}"]`
    );
    expect(row).not.toBeNull();

    const errorEvent = waitForDetailEvent(window, { status: 'error', projectId });
    row?.click();
    await errorEvent;
    await flushAsync(window);

    const status = document.querySelector('[data-project-status]');
    expect(status?.getAttribute('data-state')).toBe('error');
    expect(status?.textContent ?? '').toContain('Proje detayı alınamadı');

    const content = document.querySelector('[data-project-content]');
    expect(content?.textContent ?? '').toContain('Proje detayı alınamadı');

    const drawer = document.querySelector<HTMLElement>('[data-project-drawer]');
    expect(drawer?.hasAttribute('hidden')).toBe(false);
    expect(row?.getAttribute('aria-expanded')).toBe('true');

    const detailCalls = fetchMock.mock.calls.filter(([input]) =>
      getRequestUrl(input).includes(`/v1/projects/${projectId}`)
    );
    expect(detailCalls).toHaveLength(1);
  });
});
