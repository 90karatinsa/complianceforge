// SPDX-License-Identifier: MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const POLICIES_RESPONSE = {
  data: [
    {
      id: 'policy-1',
      name: 'Kritik CVE bloklayıcı',
      description: 'CVSS 8 üstü deny',
      updated_at: '2024-07-01T12:00:00.000Z',
      rules: {
        cvss_threshold: 8,
        allow: ['pkg:npm/*'],
        deny: ['pkg:maven/log4j'],
        opa_bundle: { status: 'ready', version: '2024.07.01' }
      }
    }
  ]
};

const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

describe('policies page', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders policies and updates search filter', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/policies')) {
        return jsonResponse(POLICIES_RESPONSE);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('policies.html', { fetchImplementation: fetchMock });
    const document = dom.window.document;

    await vi.waitFor(() => {
      const firstRow = document.querySelector('[data-policy-body] tr');
      expect(firstRow?.textContent).toContain('Kritik CVE bloklayıcı');
    });

    expect(document.querySelector('[data-opa-status]')?.textContent).toContain('Bundle senkronize');

    const search = document.querySelector('[data-search]') as HTMLInputElement;
    search.value = 'olmayan';
    search.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    await vi.waitFor(() => {
      const emptyRow = document.querySelector('[data-policy-body] tr td');
      expect(emptyRow?.textContent).toContain('Politika bulunamadı');
    });
  });

  it('creates a new policy via modal', async () => {
    const postPayloads: unknown[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/policies?')) {
        return jsonResponse(POLICIES_RESPONSE);
      }
      if (url === '/v1/policies' && init?.method === 'POST') {
        const body = init?.body ? JSON.parse(init.body as string) : {};
        postPayloads.push(body);
        return jsonResponse({ data: { ...body, id: 'policy-2', rules: body.rules } }, 201);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('policies.html', { fetchImplementation: fetchMock });
    const document = dom.window.document;

    await vi.waitFor(() => {
      const firstRow = document.querySelector('[data-policy-body] tr');
      expect(firstRow).not.toBeNull();
    });
    const createButton = document.querySelector('[data-create]') as HTMLButtonElement;
    createButton.click();

    await vi.waitFor(() => {
      const modal = document.querySelector('[data-policy-modal]');
      expect(modal?.hasAttribute('open')).toBe(true);
    });

    const nameInput = document.querySelector('[data-field-name]') as HTMLInputElement;
    const cvssInput = document.querySelector('[data-field-cvss]') as HTMLInputElement;
    const allowField = document.querySelector('[data-field-allow]') as HTMLTextAreaElement;
    const denyField = document.querySelector('[data-field-deny]') as HTMLTextAreaElement;
    const submitButton = document.querySelector('[data-modal-submit]') as HTMLButtonElement;

    nameInput.value = 'Lisans kontrolü';
    nameInput.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    cvssInput.value = '7.5';
    allowField.value = 'pkg:npm/license-checked';
    denyField.value = '';

    submitButton.click();

    await vi.waitFor(() => {
      expect(postPayloads).toHaveLength(1);
    });
    expect(postPayloads[0]).toMatchObject({
      tenant_id: '55555555-5555-4555-8555-555555555555',
      name: 'Lisans kontrolü',
      rules: {
        cvss_threshold: 7.5,
        allow: ['pkg:npm/license-checked'],
        deny: []
      }
    });

    await vi.waitFor(() => {
      const rows = Array.from(document.querySelectorAll('[data-policy-body] tr'));
      expect(rows.some((row) => row.textContent?.includes('Lisans kontrolü'))).toBe(true);
    });
  });
});
