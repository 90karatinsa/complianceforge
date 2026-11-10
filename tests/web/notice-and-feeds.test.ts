// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

type NoticeBuildResponder =
  | Response
  | { status?: number; body?: unknown }
  | ((
      payload: unknown,
      init?: RequestInit
    ) =>
      | Response
      | { status?: number; body?: unknown }
      | Promise<Response | { status?: number; body?: unknown }>);

const DEFAULT_NOTICE_BUILD_RESPONSE = {
  data: {
    document: 'NOTICE — Atlas SCA\n\nBackend taslağı üretildi.',
    version_id: null,
    finalized: false
  }
};

async function loadNoticePage(options: {
  buildResponses?: NoticeBuildResponder[];
  buildResponse?: NoticeBuildResponder;
} = {}) {
  const queue = options.buildResponses ? [...options.buildResponses] : undefined;
  const fallback = options.buildResponse ?? { status: 200, body: DEFAULT_NOTICE_BUILD_RESPONSE };

  const evaluateResponder = async (
    candidate: NoticeBuildResponder | undefined,
    payload: unknown,
    init?: RequestInit
  ): Promise<Response> => {
    const value = candidate ?? fallback;

    if (typeof value === 'function') {
      const result = await value(payload, init);
      if (result === undefined) {
        return createJsonResponse(DEFAULT_NOTICE_BUILD_RESPONSE, 200);
      }
      return evaluateResponder(result as NoticeBuildResponder | undefined, payload, init);
    }

    if (value instanceof Response) {
      return value;
    }

    if (value && typeof value === 'object') {
      return toResponse(value);
    }

    return createJsonResponse(DEFAULT_NOTICE_BUILD_RESPONSE, 200);
  };

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : String(input);
    const url = new URL(target, 'https://atlas.local');
    const method = (init?.method ?? 'GET').toUpperCase();

    if (url.pathname === '/v1/notice/build' && method === 'POST') {
      let parsedBody: unknown = undefined;
      if (typeof init?.body === 'string') {
        try {
          parsedBody = JSON.parse(init.body);
        } catch {
          parsedBody = init?.body ?? null;
        }
      } else if (init?.body instanceof ArrayBuffer) {
        parsedBody = JSON.parse(Buffer.from(init.body).toString('utf8'));
      } else if (ArrayBuffer.isView(init?.body)) {
        const view = init.body as ArrayBufferView;
        parsedBody = JSON.parse(Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString('utf8'));
      } else {
        parsedBody = init?.body ?? null;
      }

      const responder = queue && queue.length > 0 ? queue.shift() : options.buildResponse;
      return evaluateResponder(responder, parsedBody, init);
    }

    throw new Error(`Unhandled request: ${method} ${url}`);
  });

  const dom = loadPage('notice-builder.html', { fetchImplementation: fetchMock });
  const { window } = dom;

  await flushAsync(window);

  return { window, fetchMock, flush: () => flushAsync(window) } as const;
}

const TENANT_ID = '55555555-5555-4555-8555-555555555555';

const DEFAULT_FEED_RESPONSE = {
  data: [
    {
      id: 'manifest-2024-07',
      version: 'feed-2024.07.01',
      manifest: { imported_by: 'legal_ops', packages: ['osv-2024-07.json'] },
      imported_at: '2024-07-01T11:20:00.000Z',
      verified_at: '2024-07-01T11:45:00.000Z',
      signature: 'sig-1',
      minimum_downgrade_version: '2024.05'
    },
    {
      id: 'manifest-2024-06-15',
      version: 'feed-2024.06.15',
      manifest: { imported_by: 'security_ops' },
      imported_at: '2024-06-15T09:17:00.000Z',
      verified_at: '2024-06-15T09:50:00.000Z',
      signature: 'sig-2',
      minimum_downgrade_version: '2024.04'
    },
    {
      id: 'manifest-2024-06-10',
      version: 'feed-2024.06.10',
      manifest: { imported_by: 'release_ops' },
      imported_at: '2024-06-10T13:05:00.000Z',
      verified_at: null,
      signature: 'sig-3',
      minimum_downgrade_version: '2024.03'
    },
    {
      id: 'manifest-2024-06-01',
      version: 'feed-2024.06.01',
      manifest: { imported_by: 'legal_ops', notes: 'signature failure' },
      imported_at: '2024-06-01T10:03:00.000Z',
      verified_at: null,
      signature: null,
      minimum_downgrade_version: '2024.02'
    }
  ],
  pagination: { page: 1, page_size: 25 },
  active_version: 'feed-2024.07.01',
  active_minimum_downgrade_version: '2024.05'
};

const DEFAULT_MANIFEST_RESPONSES: Record<string, unknown> = {
  'manifest-2024-07': {
    manifest: {
      imported_by: 'legal_ops',
      packages: ['osv-2024-07.json'],
      signed_manifest: 'component-a@1.2.3\ncomponent-b@4.5.6\nsha256:3f4ef9a0'
    }
  },
  'manifest-2024-06-15': {
    manifest: {
      imported_by: 'security_ops',
      packages: ['osv-2024-06-15.json'],
      signed_manifest: 'component-c@2.0.0\nsha256:abc123'
    }
  },
  'manifest-2024-06-10': {
    manifest: {
      imported_by: 'release_ops',
      packages: ['osv-2024-06-10.json'],
      signed_manifest: 'component-e@3.1.4\nsha256:987654'
    }
  },
  'manifest-2024-06-01': {
    manifest: {
      imported_by: 'legal_ops',
      notes: 'signature failure',
      signed_manifest: 'component-d@0.9.1\nsha256:def456'
    }
  }
};

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

const toResponse = (config: { status?: number; body?: unknown } | Response | undefined) => {
  if (config instanceof Response) {
    return config;
  }

  const status = config?.status ?? 204;
  if (config?.body !== undefined) {
    return createJsonResponse(config.body, status);
  }

  return new Response(null, { status });
};

const flushAsync = async (_window: Window) => {
  await Promise.resolve();
  await Promise.resolve();
};

async function loadFeedsPage(options: {
  historyResponse?: typeof DEFAULT_FEED_RESPONSE;
  activateResponse?: { status?: number; body?: unknown } | Response;
  rollbackResponse?: { status?: number; body?: unknown } | Response;
  manifestResponses?: Record<string, unknown>;
  uploadResponse?:
    | Response
    | { status?: number; body?: unknown }
    | ((form: FormData, init?: RequestInit) => Response | { status?: number; body?: unknown } | Promise<Response | { status?: number; body?: unknown }>);
} = {}) {
  const historyResponse = options.historyResponse ?? DEFAULT_FEED_RESPONSE;
  const activateResponse = options.activateResponse ?? { status: 204 };
  const rollbackResponse = options.rollbackResponse ?? { status: 204 };
  const manifestResponses = options.manifestResponses ?? DEFAULT_MANIFEST_RESPONSES;
  const uploadResponse = options.uploadResponse ?? {
    status: 201,
    body: {
      manifest_id: 'manifest-2024-08',
      version: 'feed-2024.08.01',
      package_count: 1,
      vulnerability_count: 0,
      signature_verified: true
    }
  };

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : String(input);
    const url = new URL(target, 'https://atlas.local');
    const method = (init?.method ?? 'GET').toUpperCase();
    const { pathname } = url;

    if (pathname === '/v1/feeds' && method === 'GET') {
      return createJsonResponse(historyResponse, 200);
    }

    if (pathname === '/v1/feeds/activate' && method === 'POST') {
      return toResponse(activateResponse);
    }

    if (pathname === '/v1/feeds/rollback' && method === 'POST') {
      return toResponse(rollbackResponse);
    }

    if (pathname === '/v1/feeds/manifest' && method === 'GET') {
      const manifestId = url.searchParams.get('manifest_id') ?? '';
      const body = manifestResponses[manifestId] ?? manifestResponses.default;
      if (!body) {
        return new Response(null, { status: 404 });
      }

      return createJsonResponse(body, 200);
    }

    if (pathname === '/v1/feeds/upload' && method === 'POST') {
      const body = init?.body;
      const formData = body as FormData;

      const resolved =
        typeof uploadResponse === 'function'
          ? await uploadResponse(formData, init)
          : uploadResponse;

      return toResponse(resolved);
    }

    throw new Error(`Unhandled request: ${method} ${url}`);
  });

  const dom = loadPage('feeds.html', { fetchImplementation: fetchMock });
  const { window } = dom;

  await new Promise<void>((resolve) => {
    const maybeResolve = () => {
      const hasRows = window.document.querySelector(
        'table[data-table="feed-history"] tbody tr[data-manifest-id]'
      );
      if (hasRows) {
        resolve();
        return true;
      }
      return false;
    };

    if (maybeResolve()) {
      return;
    }

    const handler = () => {
      if (maybeResolve()) {
        window.document.removeEventListener('feeds:history-loaded', handler);
      }
    };

    window.document.addEventListener('feeds:history-loaded', handler, { once: true });

    queueMicrotask(() => {
      if (maybeResolve()) {
        window.document.removeEventListener('feeds:history-loaded', handler);
      }
    });
  });

  await flushAsync(window);

  return { window, fetchMock, historyResponse } as const;
}

async function waitForBuildState(
  window: Window,
  flush: () => Promise<void>,
  expectedState: string,
  attempts = 10
) {
  for (let index = 0; index < attempts; index += 1) {
    const statusElement = window.document.querySelector<HTMLElement>('[data-build-status]');
    if (statusElement) {
      if (statusElement.dataset.state === 'error' && expectedState !== 'error') {
        throw new Error(
          `Notice build errored while waiting for ${expectedState}: ${statusElement.textContent ?? 'no message'}`
        );
      }

      if (statusElement.dataset.state === expectedState) {
        return statusElement;
      }
    }

    await flush();
  }

  const finalStatus = window.document.querySelector<HTMLElement>('[data-build-status]');
  throw new Error(
    `Timed out waiting for build status ${expectedState}; last state ${finalStatus?.dataset.state ?? 'unknown'}.`
  );
}

async function waitForProgressState(window: Window, expectedState: string, attempts = 10) {
  for (let index = 0; index < attempts; index += 1) {
    const progressElement = window.document.querySelector<HTMLElement>('[data-progress]');
    if (
      progressElement &&
      progressElement.getAttribute('aria-busy') === 'false' &&
      progressElement.getAttribute('data-state') === expectedState
    ) {
      return progressElement;
    }

    if (
      progressElement &&
      progressElement.getAttribute('data-state') === 'error' &&
      expectedState !== 'error'
    ) {
      const progressText = window.document.querySelector('[data-progress-text]');
      throw new Error(
        `Feed progress errored while waiting for ${expectedState}: ${progressText?.textContent ?? 'no message'}`
      );
    }

    await flushAsync(window);
  }

  const progressElement = window.document.querySelector<HTMLElement>('[data-progress]');
  throw new Error(
    `Timed out waiting for progress state ${expectedState}; busy=${
      progressElement?.getAttribute('aria-busy') ?? 'unknown'
    }, state=${progressElement?.getAttribute('data-state') ?? 'unknown'}.`
  );
}

describe('notice builder page', () => {
  it('exposes skip link, theme toggle, and contrast tokens', async () => {
    const { window } = await loadNoticePage();
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
    expect(navElements[7]?.getAttribute('aria-current')).toBe('page');
  });

  it('lets the user configure templates and dedupe toggles', async () => {
    const { window } = await loadNoticePage();
    const { document } = window;
    const templateSelect = document.querySelector<HTMLSelectElement>('[data-template]');
    expect(templateSelect).not.toBeNull();
    const options = Array.from(templateSelect!.options).map((opt) => opt.value);
    expect(options).toEqual(['default', 'oss', 'embedded']);

    const dedupeToggle = document.querySelector<HTMLInputElement>('[data-toggle="dedupe"]');
    expect(dedupeToggle?.checked).toBe(true);
    const overrideToggle = document.querySelector<HTMLInputElement>('[data-toggle="override"]');
    expect(overrideToggle).not.toBeNull();
  });

  it('updates the preview region and diff based on inputs', async () => {
    const { window } = await loadNoticePage();
    const { document } = window;
    const preview = document.querySelector('[data-preview]');
    expect(preview).not.toBeNull();
    expect(preview?.textContent ?? '').toContain('NOTICE — Atlas SCA');
    expect(preview?.textContent ?? '').toContain('Deduplama etkin');

    const lockButton = document.querySelector('[data-action="lock"]');
    expect(lockButton).not.toBeNull();

    const diffRegion = document.querySelector('[data-diff-region]');
    expect(diffRegion?.getAttribute('aria-live')).toBe('polite');
    const diffCards = diffRegion?.querySelectorAll('[data-diff]');
    expect(diffCards?.length).toBe(2);

    const overrideToggle = document.querySelector<HTMLInputElement>('[data-toggle="override"]');
    overrideToggle?.click();
    const notesField = document.querySelector<HTMLTextAreaElement>('[data-field="notes"]');
    if (notesField) {
      notesField.value = 'Dağıtım özel notu';
      notesField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    expect(preview?.textContent ?? '').toContain('Hukuk ek açıklamaları taslağa dahil edildi.');
    expect(preview?.textContent ?? '').toContain('Dağıtım özel notu');
    const proposed = diffRegion?.querySelector('[data-diff="proposed"] pre');
    expect(proposed?.textContent ?? '').toContain('Hukuk ek açıklamaları taslağa dahil edildi.');
  });

  it('propagates project version into preview and diff captions', async () => {
    const { window } = await loadNoticePage();
    const { document } = window;
    const versionInput = document.querySelector<HTMLInputElement>('[data-field="version"]');
    expect(versionInput).not.toBeNull();

    if (versionInput) {
      versionInput.value = ' release-2.0 ';
      versionInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const preview = document.querySelector('[data-preview]');
    expect(preview?.textContent ?? '').toContain('Hedef sürüm: release-2.0');
    const diffIntro = document.querySelector('[data-diff-intro]');
    expect(diffIntro?.textContent ?? '').toContain('release-2.0');
    const proposedCaption = document.querySelector('[data-diff-version="proposed"]');
    expect(proposedCaption?.textContent ?? '').toContain('release-2.0');
    const approvedCaption = document.querySelector('[data-diff-version="approved"]');
    expect(approvedCaption?.textContent ?? '').toContain('release-2.0');
  });

  it('sends preview build requests and renders backend output', async () => {
    const { window, fetchMock, flush } = await loadNoticePage({
      buildResponse: {
        status: 200,
        body: {
          data: {
            document: 'Backend NOTICE içeriği',
            version_id: 'preview-123',
            finalized: false
          }
        }
      }
    });
    const { document } = window;

    const notesField = document.querySelector<HTMLTextAreaElement>('[data-field="notes"]');
    if (notesField) {
      notesField.value = 'Dağıtım özel notu';
      notesField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const previewButton = document.querySelector<HTMLButtonElement>('[data-action="preview"]');
    previewButton?.click();

    const statusElement = await waitForBuildState(window, flush, 'success');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.method).toBe('POST');
    const body = init?.body ? JSON.parse(init.body as string) : null;
    expect(body).toMatchObject({
      tenant_id: TENANT_ID,
      project_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      template: 'default',
      finalize: false,
      additional_text: 'Dağıtım özel notu'
    });
    expect(body).not.toHaveProperty('signoff');

    const previewRegion = document.querySelector('[data-preview]');
    expect(previewRegion?.textContent).toBe('Backend NOTICE içeriği');
    const downloadContainer = document.querySelector('[data-download-container]');
    expect(downloadContainer?.hasAttribute('hidden')).toBe(false);
    const downloadLink = document.querySelector<HTMLAnchorElement>('[data-download-link]');
    expect(downloadLink?.getAttribute('download')).toBe('notice-preview.txt');
    const downloadMeta = document.querySelector('[data-download-meta]');
    expect(downloadMeta?.textContent).toBe('Sürüm ID: preview-123');
    expect(statusElement.textContent).toBe('NOTICE taslağı güncellendi.');
    expect(statusElement.dataset.state).toBe('success');
  });

  it('requires signoff fields before locking the notice', async () => {
    const { window, fetchMock, flush } = await loadNoticePage();
    const { document } = window;
    const lockButton = document.querySelector<HTMLButtonElement>('[data-action="lock"]');
    expect(lockButton).not.toBeNull();

    lockButton?.click();
    await flush();

    expect(fetchMock).not.toHaveBeenCalled();

    const signoffNameField = document.querySelector<HTMLInputElement>('[data-signoff="name"]');
    const signoffSignatureField = document.querySelector<HTMLInputElement>('[data-signoff="signature"]');
    expect(signoffNameField?.getAttribute('aria-invalid')).toBe('true');
    expect(signoffSignatureField?.getAttribute('aria-invalid')).toBe('true');

    const buildStatus = document.querySelector('[data-build-status]');
    expect(buildStatus?.textContent).toBe('Taslağı kilitlemek için imzalayan adı ve imza gereklidir.');
    expect(buildStatus?.dataset.state).toBe('error');
    expect(lockButton?.getAttribute('aria-pressed')).toBe('false');
  });

  it('locks the notice after a successful finalize request and clears download link when unlocking', async () => {
    const { window, fetchMock, flush } = await loadNoticePage({
      buildResponse: {
        status: 200,
        body: {
          data: {
            document: 'Final NOTICE içeriği',
            version_id: 'notice-final-001',
            finalized: true
          }
        }
      }
    });
    const { document } = window;

    const versionInput = document.querySelector<HTMLInputElement>('[data-field="version"]');
    if (versionInput) {
      versionInput.value = 'release-3.0';
      versionInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const overrideToggle = document.querySelector<HTMLInputElement>('[data-toggle="override"]');
    overrideToggle?.click();

    const signoffNameField = document.querySelector<HTMLInputElement>('[data-signoff="name"]');
    const signoffEmailField = document.querySelector<HTMLInputElement>('[data-signoff="email"]');
    const signoffSignatureField = document.querySelector<HTMLInputElement>('[data-signoff="signature"]');
    if (signoffNameField) {
      signoffNameField.value = 'Ayşe Yılmaz';
      signoffNameField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }
    if (signoffEmailField) {
      signoffEmailField.value = 'legal@example.com';
      signoffEmailField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }
    if (signoffSignatureField) {
      signoffSignatureField.value = 'onay-123';
      signoffSignatureField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const lockButton = document.querySelector<HTMLButtonElement>('[data-action="lock"]');
    lockButton?.click();
    const statusElement = await waitForBuildState(window, flush, 'success');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] ?? [];
    const payload = init?.body ? JSON.parse(init.body as string) : {};
    expect(payload).toMatchObject({
      tenant_id: TENANT_ID,
      project_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      template: 'default',
      finalize: true,
      signoff: {
        signer_name: 'Ayşe Yılmaz',
        signer_email: 'legal@example.com',
        signature: 'onay-123',
        payload: {
          version: 'release-3.0',
          dedupe: true,
          include_overrides: true
        }
      }
    });

    expect(statusElement.textContent).toBe('NOTICE kilitlendi ve imzalandı.');
    expect(statusElement.dataset.state).toBe('success');
    expect(lockButton?.getAttribute('aria-pressed')).toBe('true');

    const templateSelect = document.querySelector<HTMLSelectElement>('[data-template]');
    expect(templateSelect?.disabled).toBe(true);
    const notesField = document.querySelector<HTMLTextAreaElement>('[data-field="notes"]');
    expect(notesField?.disabled).toBe(true);
    const proposedBadge = document.querySelector('[data-lock-proposed-badge]');
    expect(proposedBadge?.getAttribute('data-state')).toBe('locked');
    const approvedBadge = document.querySelector('[data-lock-approved-badge]');
    expect(approvedBadge?.textContent ?? '').toContain('Kilitleme tarihi:');
    const lockFeedback = document.querySelector('[data-lock-feedback]');
    expect(lockFeedback?.textContent ?? '').toContain('kilitlendi');

    const downloadContainer = document.querySelector('[data-download-container]');
    expect(downloadContainer?.hasAttribute('hidden')).toBe(false);
    const downloadLink = document.querySelector<HTMLAnchorElement>('[data-download-link]');
    expect(downloadLink?.getAttribute('download')).toBe('notice-notice-final-001.txt');
    const linkHref = downloadLink?.getAttribute('href') ?? '';
    if (typeof window.URL.createObjectURL === 'function') {
      expect(linkHref).toMatch(/^blob:/);
    } else {
      expect(linkHref).toMatch(/^data:text\/plain/);
    }
    const downloadMeta = document.querySelector('[data-download-meta]');
    expect(downloadMeta?.textContent).toBe('Sürüm ID: notice-final-001');

    lockButton?.click();
    await flush();

    expect(lockButton?.getAttribute('aria-pressed')).toBe('false');
    expect(templateSelect?.disabled).toBe(false);
    expect(notesField?.disabled).toBe(false);
    expect(proposedBadge?.getAttribute('data-state')).toBe('draft');
    expect(downloadContainer?.hasAttribute('hidden')).toBe(true);
    expect(downloadLink?.hasAttribute('href')).toBe(false);
    expect(downloadMeta?.textContent).toBe('');
    const unlockedStatus = document.querySelector('[data-build-status]');
    expect(unlockedStatus?.textContent).toBe('Taslak düzenlenebilir durumda.');
    expect(unlockedStatus?.dataset.state).toBe('info');
  });

  it('shows backend error responses during finalize attempts', async () => {
    const { window, fetchMock, flush } = await loadNoticePage({
      buildResponse: {
        status: 422,
        body: { message: 'İmza doğrulanamadı' }
      }
    });
    const { document } = window;

    const signoffNameField = document.querySelector<HTMLInputElement>('[data-signoff="name"]');
    const signoffEmailField = document.querySelector<HTMLInputElement>('[data-signoff="email"]');
    const signoffSignatureField = document.querySelector<HTMLInputElement>('[data-signoff="signature"]');
    if (signoffNameField) {
      signoffNameField.value = 'Mete Legal';
      signoffNameField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }
    if (signoffEmailField) {
      signoffEmailField.value = 'mete@example.com';
      signoffEmailField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }
    if (signoffSignatureField) {
      signoffSignatureField.value = 'onay-999';
      signoffSignatureField.dispatchEvent(new window.Event('input', { bubbles: true }));
    }

    const lockButton = document.querySelector<HTMLButtonElement>('[data-action="lock"]');
    lockButton?.click();
    const statusElement = await waitForBuildState(window, flush, 'error');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] ?? [];
    const payload = init?.body ? JSON.parse(init.body as string) : {};
    expect(payload?.signoff?.signature).toBe('onay-999');

    expect(statusElement.textContent).toBe('İmza doğrulanamadı');
    expect(statusElement.dataset.state).toBe('error');
    expect(lockButton?.getAttribute('aria-pressed')).toBe('false');

    const downloadContainer = document.querySelector('[data-download-container]');
    expect(downloadContainer?.hasAttribute('hidden')).toBe(true);
    const downloadLink = document.querySelector<HTMLAnchorElement>('[data-download-link]');
    expect(downloadLink?.hasAttribute('href')).toBe(false);
    const previewRegion = document.querySelector('[data-preview]');
    expect(previewRegion?.hasAttribute('aria-busy')).toBe(false);
    const nameField = document.querySelector<HTMLInputElement>('[data-signoff="name"]');
    expect(nameField?.getAttribute('aria-invalid')).toBeNull();
    expect(lockButton?.disabled).toBe(false);
  });
});

describe('feeds page', () => {
  it('renders skip link, theme toggle, and progress states', async () => {
    const { window } = await loadFeedsPage();
    const { document } = window;
    const skipLink = document.querySelector('a.skip-link');
    expect(skipLink).not.toBeNull();
    expect(skipLink?.getAttribute('href')).toBe('#main-content');

    const toggle = document.querySelector('[data-theme-toggle]');
    expect(toggle).not.toBeNull();
    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    const progress = document.querySelector('[data-progress]');
    expect(progress?.getAttribute('aria-live')).toBe('polite');
    expect(progress?.getAttribute('aria-busy')).toBe('false');
    const inlineError = document.querySelector('[data-feedback="package"]');
    expect(inlineError?.classList.contains('inline-error')).toBe(true);
    expect(inlineError?.hasAttribute('hidden')).toBe(true);

    const styleContent = document.querySelector('style')?.textContent ?? '';
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
    expect(navElements[8]?.getAttribute('aria-current')).toBe('page');
  });

  it('accepts feed package inputs and actions', async () => {
    const { window } = await loadFeedsPage();
    const { document } = window;
    const packageInput = document.querySelector<HTMLInputElement>('[data-field="package"]');
    const signatureInput = document.querySelector<HTMLInputElement>('[data-field="signature"]');
    expect(packageInput).not.toBeNull();
    expect(signatureInput).not.toBeNull();
    const actions = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-action]')).map((btn) =>
      btn.getAttribute('data-action')
    );
    expect(actions).toEqual(
      expect.arrayContaining(['validate', 'activate', 'rollback', 'view-manifest', 'details', 'close-modal'])
    );
  });

  it('lists feed history rows with status pills', async () => {
    const { window, historyResponse } = await loadFeedsPage();
    const { document } = window;
    const rows = document.querySelectorAll('table[data-table="feed-history"] tbody tr');
    expect(rows.length).toBe(historyResponse.data.length);
    rows.forEach((row) => {
      const status = row.querySelector('.status-pill');
      expect(status).not.toBeNull();
      expect(status?.getAttribute('data-status')).toMatch(/verified|failed|pending/);
    });
  });

  it('renders active downgrade floor and per-manifest rollback floors', async () => {
    const { window, historyResponse } = await loadFeedsPage();
    const { document } = window;

    const activeVersion = document.querySelector('[data-active-version]');
    const activeFloor = document.querySelector('[data-active-floor]');

    expect(activeVersion?.textContent).toBe(historyResponse.active_version);
    expect(activeFloor?.textContent).toBe(historyResponse.active_minimum_downgrade_version ?? '—');

    const rowFloors = Array.from(
      document.querySelectorAll<HTMLTableRowElement>('table[data-table="feed-history"] tbody tr')
    ).map((row) => row.querySelector('td[data-field="minimum-downgrade"]')?.textContent?.trim());

    expect(rowFloors).toEqual(
      historyResponse.data.map((entry) => entry.minimum_downgrade_version ?? '—')
    );
  });

  it('marks signed but unverified feed history rows as pending', async () => {
    const { window } = await loadFeedsPage();
    const { document } = window;
    const pendingRow = Array.from(
      document.querySelectorAll<HTMLTableRowElement>('table[data-table="feed-history"] tbody tr')
    ).find((row) => row.dataset.manifestId === 'manifest-2024-06-10');

    expect(pendingRow).toBeDefined();
    const status = pendingRow?.querySelector('.status-pill');
    expect(status?.getAttribute('data-status')).toBe('pending');
    expect(status?.textContent).toBe('İmza doğrulaması beklemede');
  });

  it('provides a manifest preview modal with accessible labelling', async () => {
    const { window } = await loadFeedsPage();
    const { document } = window;
    const modal = document.querySelector('[data-modal="manifest"]');
    expect(modal?.getAttribute('role')).toBe('dialog');
    expect(modal?.getAttribute('aria-modal')).toBe('true');
    const titleId = modal?.getAttribute('aria-labelledby');
    expect(titleId).toBe('modal-title');
    const viewButton = document.querySelector<HTMLButtonElement>('[data-action="view-manifest"]');
    const modalOpened = new Promise<void>((resolve) => {
      document.addEventListener('feeds:manifest-opened', () => resolve(), { once: true });
    });
    viewButton?.click();
    await modalOpened;
    await flushAsync(window);
    const body = modal?.querySelector('pre[data-modal-body]');
    expect(body?.textContent ?? '').toContain('component-a@1.2.3');
  });

  it('submits feed uploads as FormData and refreshes history on success', async () => {
    let currentWindow: Window | undefined;
    const uploadSpy = vi.fn((form: FormData) => {
      const tenantId = form.get('tenant_id');
      const manifest = form.get('manifest');
      const signature = form.get('signature');
      const notes = form.get('notes');

      expect(tenantId).toBe(TENANT_ID);
      const FileCtor = currentWindow?.File ?? File;
      expect(manifest).toBeInstanceOf(FileCtor);
      expect((manifest as File).name).toBe('feed.tgz');
      expect(signature).toBeInstanceOf(FileCtor);
      expect((signature as File).name).toBe('feed.sig');
      expect(notes).toBe('Temmuz feed güncellemesi');

      return {
        status: 201,
        body: {
          manifest_id: 'manifest-2024-08',
          version: 'feed-2024.08.01',
          package_count: 2,
          vulnerability_count: 5,
          signature_verified: true
        }
      };
    });

    const { window, fetchMock } = await loadFeedsPage({ uploadResponse: uploadSpy });
    currentWindow = window;
    const { document } = window;
    const packageInput = document.querySelector<HTMLInputElement>('[data-field="package"]');
    const signatureInput = document.querySelector<HTMLInputElement>('[data-field="signature"]');
    const notesField = document.querySelector<HTMLTextAreaElement>('[data-field="notes"]');
    const validateButton = document.querySelector<HTMLButtonElement>('[data-action="validate"]');

    if (packageInput) {
      Object.defineProperty(packageInput, 'files', {
        configurable: true,
        value: [new window.File(['feed-bytes'], 'feed.tgz', { type: 'application/gzip' })]
      });
      packageInput.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    if (signatureInput) {
      Object.defineProperty(signatureInput, 'files', {
        configurable: true,
        value: [new window.File(['sig'], 'feed.sig', { type: 'application/octet-stream' })]
      });
    }

    if (notesField) {
      notesField.value = 'Temmuz feed güncellemesi';
    }

    validateButton?.click();
    const progressElement = await waitForProgressState(window, 'success');

    expect(uploadSpy).toHaveBeenCalledTimes(1);
    const uploadCall = fetchMock.mock.calls.find((call) => {
      const url = new URL(call[0] as string, 'https://atlas.local');
      return url.pathname === '/v1/feeds/upload';
    });
    expect(uploadCall).toBeTruthy();

    expect(progressElement.getAttribute('aria-busy')).toBe('false');
    expect(progressElement.getAttribute('data-state')).toBe('success');
    const progressTextElement = document.querySelector('[data-progress-text]');
    expect(progressTextElement?.textContent ?? '').toContain('feed-2024.08.01');

    const historyCalls = fetchMock.mock.calls.filter((call) => {
      const url = new URL(call[0] as string, 'https://atlas.local');
      return url.pathname === '/v1/feeds';
    });
    expect(historyCalls.length).toBeGreaterThanOrEqual(2);

    if (packageInput) {
      expect(packageInput.value).toBe('');
    }
  });

  it('surfaces upload errors and restores controls', async () => {
    const { window, fetchMock } = await loadFeedsPage({
      uploadResponse: () => ({ status: 400, body: { error: { message: 'Signature required.' } } })
    });

    const { document } = window;
    const packageInput = document.querySelector<HTMLInputElement>('[data-field="package"]');
    const validateButton = document.querySelector<HTMLButtonElement>('[data-action="validate"]');
    const activateButton = document.querySelector<HTMLButtonElement>('[data-action="activate"]');

    if (packageInput) {
      Object.defineProperty(packageInput, 'files', {
        configurable: true,
        value: [new window.File(['feed-bytes'], 'feed.tgz', { type: 'application/gzip' })]
      });
      packageInput.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    validateButton?.click();
    const errorProgressElement = await waitForProgressState(window, 'error');

    expect(errorProgressElement.getAttribute('aria-busy')).toBe('false');
    expect(errorProgressElement.getAttribute('data-state')).toBe('error');
    const errorProgressText = document.querySelector('[data-progress-text]');
    expect(errorProgressText?.textContent ?? '').toContain('Signature required');
    expect(validateButton?.disabled).toBe(false);
    expect(activateButton?.disabled).toBe(false);

    const uploadCalls = fetchMock.mock.calls.filter((call) => {
      const url = new URL(call[0] as string, 'https://atlas.local');
      return url.pathname === '/v1/feeds/upload';
    });
    expect(uploadCalls).toHaveLength(1);
  });

  it('traps focus in the manifest modal and restores background state', async () => {
    const { window } = await loadFeedsPage();
    const { document } = window;
    const viewButton = document.querySelector<HTMLButtonElement>('[data-action="view-manifest"]');
    const modal = document.querySelector('[data-modal="manifest"]');
    const closeButton = modal?.querySelector<HTMLButtonElement>('[data-action="close-modal"]');
    const header = document.querySelector('header.global-header');
    const main = document.getElementById('main-content');
    const footer = document.querySelector('footer.global-footer');

    const modalOpened = new Promise<void>((resolve) => {
      document.addEventListener('feeds:manifest-opened', () => resolve(), { once: true });
    });
    viewButton?.click();
    await modalOpened;
    await flushAsync(window);
    expect(modal?.hasAttribute('hidden')).toBe(false);
    expect(header?.getAttribute('aria-hidden')).toBe('true');
    expect(main?.getAttribute('aria-hidden')).toBe('true');
    expect(footer?.getAttribute('aria-hidden')).toBe('true');
    expect(header?.hasAttribute('inert')).toBe(true);
    expect(main?.hasAttribute('inert')).toBe(true);
    expect(footer?.hasAttribute('inert')).toBe(true);
    expect((header as HTMLElement & { inert?: boolean })?.inert).toBe(true);
    expect((main as HTMLElement & { inert?: boolean })?.inert).toBe(true);
    expect((footer as HTMLElement & { inert?: boolean })?.inert).toBe(true);
    expect(document.activeElement).toBe(closeButton);

    document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Tab' }));
    expect(document.activeElement).toBe(closeButton);

    closeButton?.click();
    await flushAsync(window);
    expect(modal?.hasAttribute('hidden')).toBe(true);
    expect(header?.hasAttribute('inert')).toBe(false);
    expect(header?.getAttribute('aria-hidden')).toBeNull();
    expect((header as HTMLElement & { inert?: boolean })?.inert).toBe(false);
    expect(document.activeElement).toBe(viewButton);
  });

  it('reveals package errors only after validation attempts', async () => {
    const { window } = await loadFeedsPage();
    const { document } = window;
    const packageError = document.querySelector('[data-feedback="package"]');
    const packageInput = document.querySelector<HTMLInputElement>('[data-field="package"]');
    const validateButton = document.querySelector<HTMLButtonElement>('[data-action="validate"]');
    const activateButton = document.querySelector<HTMLButtonElement>('[data-action="activate"]');

    expect(packageError?.hasAttribute('hidden')).toBe(true);

    validateButton?.click();
    expect(packageError?.hasAttribute('hidden')).toBe(false);
    expect(packageError?.textContent ?? '').toContain('Dosya seçilmedi');
    expect(packageInput?.getAttribute('aria-invalid')).toBe('true');

    if (packageInput) {
      Object.defineProperty(packageInput, 'files', {
        configurable: true,
        value: [new window.File(['feed'], 'feed.tgz', { type: 'application/gzip' })]
      });
      packageInput.dispatchEvent(new window.Event('change', { bubbles: true }));
    }

    expect(packageError?.hasAttribute('hidden')).toBe(true);

    activateButton?.click();
    expect(packageError?.hasAttribute('hidden')).toBe(true);
    expect(packageInput?.getAttribute('aria-invalid')).toBeNull();
  });

  it('posts activation and rollback requests with status feedback', async () => {
    const { window, fetchMock } = await loadFeedsPage();
    const { document } = window;
    const progress = document.querySelector('[data-progress]');
    const progressText = document.querySelector('[data-progress-text]');
    const getRowByManifest = (manifestId: string) =>
      document.querySelector<HTMLTableRowElement>(
        `table[data-table="feed-history"] tbody tr[data-manifest-id="${manifestId}"]`
      );

    const activateRow = getRowByManifest('manifest-2024-06-15');
    const secondActivate = activateRow?.querySelector<HTMLButtonElement>('[data-action="activate"][data-context="history"]');
    const historyReloadAfterActivate = new Promise<void>((resolve) => {
      document.addEventListener('feeds:history-loaded', () => resolve(), { once: true });
    });
    secondActivate?.click();
    expect(progress?.dataset.state).toBe('running');
    expect(progress?.getAttribute('aria-busy')).toBe('true');
    await historyReloadAfterActivate;
    await waitForProgressState(window, 'success');
    expect(progressText?.textContent ?? '').toContain('aktif hale getirildi');

    const activateCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/v1/feeds/activate'));
    expect(activateCall).toBeDefined();
    const activatePayload = activateCall ? JSON.parse((activateCall[1]?.body as string) ?? '{}') : {};
    expect(activatePayload).toMatchObject({
      tenant_id: TENANT_ID,
      manifest_id: 'manifest-2024-06-15',
      version: 'feed-2024.06.15'
    });

    const rollbackRow = getRowByManifest('manifest-2024-06-01');
    const thirdRollback = rollbackRow?.querySelector<HTMLButtonElement>('[data-action="rollback"]');
    const historyReloadAfterRollback = new Promise<void>((resolve) => {
      document.addEventListener('feeds:history-loaded', () => resolve(), { once: true });
    });
    thirdRollback?.click();
    expect(progress?.dataset.state).toBe('warning');
    expect(progress?.getAttribute('aria-busy')).toBe('true');
    await historyReloadAfterRollback;
    await waitForProgressState(window, 'success');
    expect(progressText?.textContent ?? '').toContain('geri yüklendi');

    const rollbackCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/v1/feeds/rollback'));
    expect(rollbackCall).toBeDefined();
    const rollbackPayload = rollbackCall ? JSON.parse((rollbackCall[1]?.body as string) ?? '{}') : {};
    expect(rollbackPayload).toMatchObject({
      tenant_id: TENANT_ID,
      manifest_id: 'manifest-2024-06-01',
      version: 'feed-2024.06.01'
    });

    const detailButton = document.querySelector<HTMLButtonElement>('[data-action="details"]');
    const historyFeedback = document.querySelector('[data-history-feedback]');
    const historyTitle = historyFeedback?.querySelector('[data-history-title]');
    const historyDetails = historyFeedback?.querySelector('[data-history-text]');
    detailButton?.click();
    await flushAsync(window);
    expect(historyFeedback?.hasAttribute('hidden')).toBe(false);
    expect(historyTitle?.textContent ?? '').toContain('feed-2024.06.01');
    expect(historyDetails?.textContent ?? '').toContain('İçe aktaran: legal_ops');
    expect(detailButton?.getAttribute('aria-expanded')).toBe('true');
  });

  it('omits version from activation payloads when history entries lack version metadata', async () => {
    const missingVersionHistory = {
      ...DEFAULT_FEED_RESPONSE,
      data: [
        {
          id: 'manifest-2024-08',
          version: null as unknown as string,
          manifest: { imported_by: 'security_ops' },
          imported_at: '2024-08-01T08:00:00.000Z',
          verified_at: '2024-08-01T08:20:00.000Z',
          signature: 'sig-latest'
        },
        ...DEFAULT_FEED_RESPONSE.data
      ]
    } as unknown as typeof DEFAULT_FEED_RESPONSE;

    const manifestResponses = {
      ...DEFAULT_MANIFEST_RESPONSES,
      'manifest-2024-08': { manifest: { imported_by: 'security_ops', packages: [] } }
    };

    const { window, fetchMock } = await loadFeedsPage({
      historyResponse: missingVersionHistory,
      manifestResponses
    });
    const { document } = window;
    const progressText = document.querySelector('[data-progress-text]');
    const targetRow = document.querySelector<HTMLTableRowElement>(
      'table[data-table="feed-history"] tbody tr[data-manifest-id="manifest-2024-08"]'
    );

    expect(targetRow).not.toBeNull();
    expect(targetRow?.dataset.version).toBeUndefined();

    const activateButton = targetRow?.querySelector<HTMLButtonElement>(
      '[data-action="activate"][data-context="history"]'
    );

    const historyReload = new Promise<void>((resolve) => {
      document.addEventListener('feeds:history-loaded', () => resolve(), { once: true });
    });

    activateButton?.click();
    await historyReload;
    await waitForProgressState(window, 'success');

    const activateCall = fetchMock.mock.calls
      .filter(([input]) => String(input).endsWith('/v1/feeds/activate'))
      .pop();
    expect(activateCall).toBeDefined();
    const activatePayload = activateCall ? JSON.parse((activateCall[1]?.body as string) ?? '{}') : {};
    expect(activatePayload).toEqual({ tenant_id: TENANT_ID, manifest_id: 'manifest-2024-08' });
    expect(progressText?.textContent ?? '').toContain('Bilinmeyen sürüm');
  });

  it('treats blank history versions as unknown while keeping fallback messaging', async () => {
    const blankVersionHistory = {
      ...DEFAULT_FEED_RESPONSE,
      data: [
        {
          id: 'manifest-2024-09',
          version: '  ',
          manifest: { imported_by: 'compliance_ops' },
          imported_at: '2024-09-01T09:00:00.000Z',
          verified_at: '2024-09-01T09:15:00.000Z',
          signature: 'sig-blank'
        },
        ...DEFAULT_FEED_RESPONSE.data
      ]
    } as unknown as typeof DEFAULT_FEED_RESPONSE;

    const manifestResponses = {
      ...DEFAULT_MANIFEST_RESPONSES,
      'manifest-2024-09': { manifest: { imported_by: 'compliance_ops', packages: [] } }
    };

    const { window, fetchMock } = await loadFeedsPage({
      historyResponse: blankVersionHistory,
      manifestResponses
    });

    const { document } = window;
    const historyFeedback = document.querySelector('[data-history-feedback]');
    const historyTitle = historyFeedback?.querySelector('[data-history-title]');
    const progressText = document.querySelector('[data-progress-text]');
    const targetRow = document.querySelector<HTMLTableRowElement>(
      'table[data-table="feed-history"] tbody tr[data-manifest-id="manifest-2024-09"]'
    );

    expect(targetRow).not.toBeNull();
    expect(targetRow?.dataset.version).toBeUndefined();

    const versionCell = targetRow?.querySelector<HTMLElement>('[data-field="version"]');
    expect(versionCell?.textContent?.trim()).toBe('—');

    const detailButton = targetRow?.querySelector<HTMLButtonElement>('[data-action="details"]');
    detailButton?.click();
    await flushAsync(window);
    expect(historyTitle?.textContent ?? '').toBe('Bilinmeyen sürüm');

    const activateButton = targetRow?.querySelector<HTMLButtonElement>('[data-action="activate"][data-context="history"]');

    const historyReload = new Promise<void>((resolve) => {
      document.addEventListener('feeds:history-loaded', () => resolve(), { once: true });
    });

    activateButton?.click();
    await historyReload;
    await waitForProgressState(window, 'success');

    const activateCall = fetchMock.mock.calls
      .filter(([input]) => String(input).endsWith('/v1/feeds/activate'))
      .pop();
    expect(activateCall).toBeDefined();
    const activatePayload = activateCall ? JSON.parse((activateCall[1]?.body as string) ?? '{}') : {};
    expect(activatePayload).toEqual({ tenant_id: TENANT_ID, manifest_id: 'manifest-2024-09' });
    expect(progressText?.textContent ?? '').toContain('Bilinmeyen sürüm');
  });

  it('fetches manifest details before opening the modal and caches responses', async () => {
    const manifestResponses = {
      ...DEFAULT_MANIFEST_RESPONSES,
      'manifest-2024-07': { signed_manifest: '-----BEGIN MANIFEST-----\nSIGNED\n-----END MANIFEST-----' }
    };

    const { window, fetchMock } = await loadFeedsPage({ manifestResponses });
    const { document } = window;

    const viewButton = document.querySelector<HTMLButtonElement>(
      'table[data-table="feed-history"] tbody tr[data-manifest-id="manifest-2024-07"] [data-action="view-manifest"]'
    );

    expect(viewButton).toBeInstanceOf(window.HTMLButtonElement);

    const modalOpened = new Promise<void>((resolve) => {
      document.addEventListener('feeds:manifest-opened', () => resolve(), { once: true });
    });
    viewButton?.click();
    await modalOpened;
    await flushAsync(window);

    const modal = document.querySelector('[data-modal="manifest"]');
    const modalBody = modal?.querySelector('pre[data-modal-body]');

    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/v1/feeds/manifest'))).toBe(true);
    const manifestCalls = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes('/v1/feeds/manifest')
    );
    expect(manifestCalls).toHaveLength(1);
    expect(modalBody?.textContent ?? '').toContain('SIGNED');

    const reopened = new Promise<void>((resolve) => {
      document.addEventListener('feeds:manifest-opened', () => resolve(), { once: true });
    });
    viewButton?.click();
    await reopened;
    await flushAsync(window);

    const manifestCallsAfterSecondClick = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes('/v1/feeds/manifest')
    );
    expect(manifestCallsAfterSecondClick).toHaveLength(1);
  });
});
