// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const TENANT_ID = '55555555-5555-4555-8555-555555555555';

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

describe('Settings & access UI', () => {
  const flush = async (window: Window) => new Promise<void>((resolve) => window.setTimeout(resolve, 0));

  it('renders API keys and supports creation and deletion workflows', async () => {
    const keysState = [
      {
        id: 'key-existing',
        name: 'CI Gateway',
        roles: ['Admin'],
        created_at: '2024-07-10T12:00:00.000Z',
        last_used_at: null,
        masked_token: '•••• 1111',
        last_four: '1111'
      }
    ];

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(typeof input === 'string' ? input : (input as Request).url, 'https://atlas.local');
      if (url.pathname === '/v1/api-keys' && (!init || !init.method || init.method === 'GET')) {
        return createJsonResponse({
          data: keysState.map((entry) => ({ ...entry })),
          pagination: { page: 1, page_size: 20, count: keysState.length }
        });
      }

      if (url.pathname === '/v1/api-keys' && init?.method === 'POST') {
        const payload = init.body ? JSON.parse(String(init.body)) : {};
        keysState.unshift({
          id: 'key-new',
          name: payload.name,
          roles: payload.roles,
          created_at: '2024-07-12T09:00:00.000Z',
          last_used_at: null,
          masked_token: '•••• 2222',
          last_four: '2222'
        });
        return createJsonResponse({ data: { plaintext_token: 'aka_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } }, 201);
      }

      if (url.pathname === '/v1/api-keys/key-new' && init?.method === 'DELETE') {
        const index = keysState.findIndex((entry) => entry.id === 'key-new');
        if (index >= 0) {
          keysState.splice(index, 1);
        }
        return new Response(null, { status: 204 });
      }

      return new Response(null, { status: 404 });
    });

    const dom = loadPage('settings.html', {
      fetchImplementation: fetchMock
    });

    const { document, navigator } = dom.window;
    const scriptErrors: unknown[] = [];
    dom.window.addEventListener('error', (event) => {
      scriptErrors.push(event.error ?? event.message);
    });
    const originalConsoleError = dom.window.console.error;
    dom.window.console.error = (...args: unknown[]) => {
      scriptErrors.push(args);
      return originalConsoleError.apply(dom.window.console, args as []);
    };
    expect(document.documentElement.dataset.tenantId).toBe(TENANT_ID);
    expect(typeof dom.window.fetch).toBe('function');
    if (!navigator.clipboard) {
      // Provide a no-op clipboard to avoid warnings during tests.
      Object.assign(navigator, {
        clipboard: {
          writeText: vi.fn().mockResolvedValue(undefined)
        }
      });
    }

    try {
      await vi.waitUntil(() => fetchMock.mock.calls.some(([, init]) => (init?.method ?? 'GET') === 'GET'), {
        timeout: 3000,
        interval: 25
      });
    } catch (error) {
      throw new Error(`API anahtarı isteği tetiklenmedi. Hatalar: ${JSON.stringify(scriptErrors)}\n${String(error)}`);
    }

    await vi.waitUntil(() => document.querySelectorAll('[data-key-table] tr').length > 0);

    const rows = document.querySelectorAll('[data-key-table] tr');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.textContent).toContain('CI Gateway');
    const initialCall = fetchMock.mock.calls.find(([, init]) => (init?.method ?? 'GET') === 'GET');
    expect(initialCall).toBeDefined();
    if (initialCall) {
      const [request] = initialCall as [RequestInfo | URL, RequestInit | undefined];
      const url = new URL(typeof request === 'string' ? request : (request as Request).url, 'https://atlas.local');
      expect(url.pathname).toBe('/v1/api-keys');
      expect(url.searchParams.get('tenant_id')).toBe(TENANT_ID);
    }

    const nameInput = document.querySelector<HTMLInputElement>('#key-name');
    nameInput?.focus();
    nameInput?.setAttribute('value', 'Pipeline Token');
    if (nameInput) {
      nameInput.value = 'Pipeline Token';
    }

    const developerCheckbox = document.querySelector<HTMLInputElement>("input[name='roles'][value='Developer']");
    if (developerCheckbox) {
      developerCheckbox.checked = true;
    }

    const form = document.querySelector<HTMLFormElement>('[data-create-form]');
    form?.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));

    await flush(dom.window);
    await flush(dom.window);

    const postCall = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(postCall).toBeDefined();
    if (postCall) {
      const [, init] = postCall as [RequestInfo | URL, RequestInit];
      expect(init?.headers).toMatchObject({ 'Content-Type': 'application/json' });
      const parsed = init?.body ? JSON.parse(String(init.body)) : {};
      expect(parsed).toMatchObject({
        tenant_id: TENANT_ID,
        name: 'Pipeline Token'
      });
      expect(parsed.roles).toContain('Developer');
    }

    const modal = document.querySelector<HTMLElement>('[data-token-modal]');
    expect(modal?.hidden).toBe(false);
    expect(modal?.textContent).toContain('aka_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

    const deleteButton = document.querySelector<HTMLButtonElement>('[data-remove-key="key-new"]');
    deleteButton?.click();
    await flush(dom.window);
    await flush(dom.window);

    const deleteCall = fetchMock.mock.calls.find(([input, init]) => {
      const url = new URL(typeof input === 'string' ? input : (input as Request).url, 'https://atlas.local');
      return url.pathname === '/v1/api-keys/key-new' && init?.method === 'DELETE';
    });
    expect(deleteCall).toBeDefined();
  });
});
