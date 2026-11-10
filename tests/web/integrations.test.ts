// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const WEBHOOKS_RESPONSE = {
  data: [
    {
      id: 'wh-1',
      url: 'https://hooks.example.com/atlas',
      events: ['scan.completed'],
      deliveries: { success: 5, failed: 1 }
    }
  ]
};

const ARTIFACT_RESPONSE = {
  status: 'allow',
  message: 'Tüm kontroller geçti'
};

const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

describe('integrations page', () => {
  let clipboardWrite: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    clipboardWrite = vi.fn(() => Promise.resolve());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('loads webhooks and artifact gate data', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/webhooks')) {
        return jsonResponse(WEBHOOKS_RESPONSE);
      }
      if (url === '/v1/integrations/artifact-gate') {
        return jsonResponse(ARTIFACT_RESPONSE);
      }
      if (url === '/v1/webhooks' && init?.method === 'POST') {
        return jsonResponse({ data: { id: 'wh-2', url: 'https://hooks.example.com/new', events: ['scan.failed'], deliveries: { success: 0, failed: 0 } } }, 201);
      }
      if (url === '/v1/webhooks/wh-1' && init?.method === 'DELETE') {
        return new Response(null, { status: 204 });
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('integrations.html', { fetchImplementation: fetchMock });
    Object.assign(dom.window.navigator, { clipboard: { writeText: clipboardWrite } });

    const document = dom.window.document;

    await vi.waitFor(() => {
      expect(document.querySelector('[data-webhook-body]')?.textContent).toContain('hooks.example.com/atlas');
    });
    expect(document.querySelector('[data-artifact-status]')?.textContent).toBe('allow');

    const copyButton = document.querySelector('[data-copy-ticket]') as HTMLButtonElement;
    copyButton.click();
    await vi.waitFor(() => {
      expect(clipboardWrite).toHaveBeenCalled();
    });
  });

  it('creates and deletes webhooks via the form', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/webhooks?')) {
        return jsonResponse(WEBHOOKS_RESPONSE);
      }
      if (url === '/v1/integrations/artifact-gate') {
        return jsonResponse(ARTIFACT_RESPONSE);
      }
      if (url === '/v1/webhooks' && init?.method === 'POST') {
        return jsonResponse({ data: { id: 'wh-2', url: 'https://hooks.example.com/new', events: ['scan.failed'], deliveries: { success: 0, failed: 0 } } }, 201);
      }
      if (url === '/v1/webhooks/wh-2' && init?.method === 'DELETE') {
        return new Response(null, { status: 204 });
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('integrations.html', { fetchImplementation: fetchMock });
    Object.assign(dom.window.navigator, { clipboard: { writeText: clipboardWrite } });

    const document = dom.window.document;

    await vi.waitFor(() => {
      const rows = document.querySelectorAll('[data-webhook-body] tr');
      expect(rows.length).toBeGreaterThan(0);
    });
    const urlField = document.querySelector('[data-field-url]') as HTMLInputElement;
    const eventsSelect = document.querySelector('[data-field-events]') as HTMLSelectElement;
    const form = document.querySelector('[data-webhook-form]') as HTMLFormElement;

    urlField.value = 'https://hooks.example.com/new';
    eventsSelect.options[1].selected = true;
    form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));

    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/v1/webhooks', expect.objectContaining({ method: 'POST' }));
    });
    await vi.waitFor(() => {
      const rowsAfterCreate = Array.from(document.querySelectorAll('[data-webhook-body] tr'));
      expect(rowsAfterCreate.some((row) => row.textContent?.includes('hooks.example.com/new'))).toBe(true);
    });

    const rowsAfterCreate = Array.from(document.querySelectorAll('[data-webhook-body] tr'));
    const deleteButton = rowsAfterCreate
      .find((row) => row.textContent?.includes('hooks.example.com/new'))
      ?.querySelector('button.secondary') as HTMLButtonElement;
    deleteButton.click();

    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/v1/webhooks/wh-2', expect.objectContaining({ method: 'DELETE' }));
    });
  });
});
