// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const TENANT_ID = '55555555-5555-4555-8555-555555555555';

const DEFAULT_PENDING_RESPONSE = {
  data: [
    {
      id: 'finding-license-001',
      tenant_id: TENANT_ID,
      license_id: 'GPL-3.0-only',
      vuln_id: null,
      scan_id: 'scan-001',
      status: 'pending',
      obligations: {
        license: 'GPL-3.0-only',
        component: 'core-api',
        severity: 'high',
        recommended_decision: 'conditional',
        recommended_label: 'Conditional (source offer)',
        notes: 'Kaynak kodu sağlanmalı.'
      },
      notes: 'Kaynak kodu sağlanmalı.',
      created_at: '2024-07-01T10:00:00.000Z',
      decision: null,
      decided_at: null,
      rationale: null
    },
    {
      id: 'finding-vuln-002',
      tenant_id: TENANT_ID,
      license_id: null,
      vuln_id: 'CVE-2024-12345',
      scan_id: 'scan-002',
      status: 'pending',
      obligations: {
        license: 'CVE-2024-12345',
        component: 'mobile-app',
        severity: 'critical',
        recommended_decision: 'allow',
        recommended_label: 'Allow (VEX mitigasyon)',
        notes: 'VEX Not Affected beyanı bekleniyor.'
      },
      notes: 'VEX Not Affected beyanı bekleniyor.',
      created_at: '2024-07-02T11:00:00.000Z',
      decision: null,
      decided_at: null,
      rationale: null
    },
    {
      id: 'finding-license-003',
      tenant_id: TENANT_ID,
      license_id: 'LGPL-2.1-only',
      vuln_id: null,
      scan_id: 'scan-003',
      status: 'pending',
      obligations: {
        license: 'LGPL-2.1-only',
        component: 'cli-tooling',
        severity: 'low',
        recommended_decision: 'allow',
        recommended_label: 'Allow (NOTICE)',
        notes: 'NOTICE çıktısına paket eklenmeli.'
      },
      notes: 'NOTICE çıktısına paket eklenmeli.',
      created_at: '2024-07-03T09:30:00.000Z',
      decision: 'allow',
      decided_at: '2024-07-03T09:45:00.000Z',
      rationale: 'NOTICE güncellendi.'
    }
  ],
  pagination: { page: 1, page_size: 20 }
} as const;

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const flushAsync = async (_window: Window) => {
  await Promise.resolve();
  await Promise.resolve();
};

async function loadLegalReviewPage(options: {
  pendingResponse?: typeof DEFAULT_PENDING_RESPONSE;
  decisionResponse?: { status?: number; body?: unknown };
} = {}) {
  const pendingResponse = options.pendingResponse ?? DEFAULT_PENDING_RESPONSE;
  const decisionResponse = options.decisionResponse ?? { status: 201, body: { id: 'decision-1' } };
  const decisionCalls: string[] = [];

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.toString() : String(input);
    const url = new URL(target, 'https://atlas.local');
    const method = (init?.method ?? 'GET').toUpperCase();

    if (url.pathname === '/v1/legal/findings' && method === 'GET') {
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
      expect(url.searchParams.get('status')).toBe('pending');
      return createJsonResponse(pendingResponse, 200);
    }

    if (url.pathname === '/v1/legal/decisions' && method === 'POST') {
      const body = typeof init?.body === 'string' ? init.body : '';
      decisionCalls.push(body);
      return createJsonResponse(decisionResponse.body ?? {}, decisionResponse.status ?? 201);
    }

    throw new Error(`Unhandled request: ${method} ${url}`);
  });

  const dom = loadPage('legal-review.html', { fetchImplementation: fetchMock });
  const { window } = dom;

  await new Promise<void>((resolve) => {
    const checkReady = () => {
      const item = window.document.querySelector('[data-queue="item"]');
      if (item) {
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
        window.document.removeEventListener('legal:queue-loaded', handler as EventListener);
      }
    };

    window.document.addEventListener('legal:queue-loaded', handler as EventListener);
    queueMicrotask(() => {
      if (checkReady()) {
        window.document.removeEventListener('legal:queue-loaded', handler as EventListener);
      }
    });
  });

  await flushAsync(window);

  return { window, fetchMock, decisionCalls } as const;
}

describe('legal review page', () => {
  it('provides skip link, theme toggle, and error summary region', async () => {
    const { window } = await loadLegalReviewPage();
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
    expect(navElements[4]?.getAttribute('aria-current')).toBe('page');

    const summary = document.querySelector('[data-error-summary]');
    expect(summary?.getAttribute('role')).toBe('alert');
    expect(summary?.getAttribute('aria-live')).toBe('assertive');
    expect(summary?.hasAttribute('hidden')).toBe(true);
    expect(summary?.querySelectorAll('li')).toHaveLength(0);

    const disclaimer = document.querySelector('[data-legal-disclaimer]');
    expect(disclaimer).not.toBeNull();
    expect(disclaimer?.textContent ?? '').toMatch(/hukuki tavsiye değildir/i);
    const form = document.getElementById('legal-form');
    expect(form?.getAttribute('aria-describedby')?.split(/\s+/u)).toContain('legal-disclaimer');
    expect(disclaimer?.getAttribute('role')).toBe('note');
  });

  it('summarises queue counts with aria-live updates', async () => {
    const { window } = await loadLegalReviewPage();
    const { document } = window;
    const counters = Array.from(document.querySelectorAll('[data-counter]'));
    expect(counters).toHaveLength(3);
    const values = counters.map((counter) => counter.querySelector('strong')?.textContent ?? '0');
    expect(values).toEqual(['2', '1', '1']);
  });

  it('lists pending findings with keyboard focus support', async () => {
    const { window } = await loadLegalReviewPage();
    const { document } = window;
    const items = Array.from(document.querySelectorAll('[data-queue="item"]'));
    expect(items).toHaveLength(3);
    const contexts = items.map((item) => item.querySelector('h3')?.textContent ?? '');
    expect(contexts).toEqual([
      'core-api — GPL-3.0-only',
      'mobile-app — CVE-2024-12345',
      'cli-tooling — LGPL-2.1-only'
    ]);
  });

  it('contains a decision form with decision radios and signoff fields', async () => {
    const { window } = await loadLegalReviewPage();
    const { document } = window;
    const decisions = document.querySelectorAll<HTMLInputElement>('[data-decision]');
    const values = Array.from(decisions).map((input) => input.value);
    expect(values).toEqual(['allow', 'deny', 'conditional']);

    const signoffFields = ['name', 'email', 'passcode'];
    signoffFields.forEach((field) => {
      expect(document.querySelector(`[data-signoff="${field}"]`)).not.toBeNull();
    });

    const submitButton = document.querySelector('[data-action="submit-decision"]');
    expect(submitButton).not.toBeNull();

    const form = document.getElementById('legal-form');
    expect(form?.getAttribute('aria-describedby')).toContain('decision-errors');
  });

  it('validates decision submissions and announces success', async () => {
    const { window, decisionCalls } = await loadLegalReviewPage();
    const { document } = window;
    const form = document.getElementById('legal-form');
    const errorSummary = document.querySelector('[data-error-summary]');
    const errorList = errorSummary?.querySelector('[data-error-list]');
    const successSummary = document.querySelector('[data-success]');

    form?.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    expect(errorSummary?.hasAttribute('hidden')).toBe(false);
    expect(errorList?.childElementCount).toBeGreaterThanOrEqual(1);

    const firstDecision = document.querySelector<HTMLInputElement>('[data-decision]');
    firstDecision && (firstDecision.checked = true);
    const notesField = document.querySelector<HTMLTextAreaElement>('#decision-notes');
    if (notesField) {
      notesField.value = 'Kaynak kodu sağlanacak.';
    }
    const nameField = document.querySelector<HTMLInputElement>('[data-signoff="name"]');
    const emailField = document.querySelector<HTMLInputElement>('[data-signoff="email"]');
    const passcodeField = document.querySelector<HTMLInputElement>('[data-signoff="passcode"]');
    if (nameField) nameField.value = 'Ayşe Hukukçu';
    if (emailField) emailField.value = 'ayse@example.com';
    if (passcodeField) passcodeField.value = '123456';

    const decisionRecorded = new Promise<void>((resolve) => {
      document.addEventListener('legal:decision-recorded', () => resolve(), { once: true });
    });

    form?.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await decisionRecorded;
    await flushAsync(window);

    expect(errorSummary?.hasAttribute('hidden')).toBe(true);
    expect(successSummary?.hasAttribute('hidden')).toBe(false);
    expect(successSummary?.textContent ?? '').toContain('Allow kararı kaydedildi');
    expect(decisionCalls).toHaveLength(1);
    const payload = JSON.parse(decisionCalls[0] ?? '{}');
    expect(payload).toMatchObject({
      tenant_id: TENANT_ID,
      decision: 'allow',
      signoff: { signer_name: 'Ayşe Hukukçu', signature: '123456' }
    });
  });

  it('prefills the decision form when queue items are selected', async () => {
    const { window } = await loadLegalReviewPage();
    const { document } = window;
    const queueItems = Array.from(document.querySelectorAll<HTMLElement>('[data-queue="item"]'));
    expect(queueItems).toHaveLength(3);

    const findingIdField = document.querySelector<HTMLInputElement>('[data-field="finding-id"]');
    const findingPackageField = document.querySelector<HTMLInputElement>('[data-field="finding-package"]');
    const notesField = document.querySelector<HTMLTextAreaElement>('#decision-notes');
    const radios = Array.from(document.querySelectorAll<HTMLInputElement>('[data-decision]'));
    const feedback = document.querySelector('[data-selection-feedback]');

    expect(queueItems[0]?.classList.contains('is-active')).toBe(true);
    expect(findingIdField?.value).toBe('finding-license-001');
    expect(findingPackageField?.value).toBe('core-api');
    expect(notesField?.value ?? '').toContain('Kaynak kodu');
    expect(radios.find((radio) => radio.value === 'conditional')?.checked).toBe(true);
    expect(feedback?.textContent ?? '').toContain('CONDITIONAL');

    queueItems[1]?.click();
    expect(queueItems[0]?.classList.contains('is-active')).toBe(false);
    expect(queueItems[1]?.classList.contains('is-active')).toBe(true);
    expect(findingIdField?.value).toBe('finding-vuln-002');
    expect(notesField?.value ?? '').toContain('VEX');
    expect(radios.find((radio) => radio.value === 'allow')?.checked).toBe(true);

    queueItems[2]?.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(queueItems[2]?.classList.contains('is-active')).toBe(true);
    expect(findingIdField?.value).toBe('finding-license-003');
    expect(feedback?.textContent ?? '').toContain('LGPL-2.1-only');
  });
});
