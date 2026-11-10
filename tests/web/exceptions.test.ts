// SPDX-License-Identifier: MIT

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const NOW = new Date('2024-07-05T10:00:00.000Z');

const EXCEPTIONS_RESPONSE = {
  data: [
    {
      id: 'exc-1',
      component_purl: 'pkg:npm/left-pad',
      scope: 'package',
      status: 'pending',
      expires_at: '2024-07-07T12:00:00.000Z',
      project_id: null,
      metadata: {}
    }
  ]
};

const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

describe('exceptions page', () => {
  beforeEach(() => {
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('renders exception list and applies filters', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/exceptions')) {
        return jsonResponse(EXCEPTIONS_RESPONSE);
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('exceptions.html', { fetchImplementation: fetchMock });
    const document = dom.window.document;

    await vi.waitFor(() => {
      const firstRow = document.querySelector('[data-exception-body] tr');
      expect(firstRow?.textContent).toContain('pkg:npm/left-pad');
      expect(firstRow?.textContent).toContain('pending');
    });

    const statusSelect = document.querySelector('[data-filter-status]') as HTMLSelectElement;
    statusSelect.value = 'approved';
    document.querySelector('[data-filter-form]')?.dispatchEvent(new dom.window.Event('submit', { bubbles: true }));
    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/v1/exceptions?tenant_id=55555555-5555-4555-8555-555555555555&status=approved'),
        expect.anything()
      );
    });
  });

  it('approves an exception via modal', async () => {
    const putPayloads: unknown[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : '';
      if (url.startsWith('/v1/exceptions?')) {
        return jsonResponse(EXCEPTIONS_RESPONSE);
      }
      if (url === '/v1/exceptions/exc-1' && init?.method === 'PUT') {
        const body = init?.body ? JSON.parse(init.body as string) : {};
        putPayloads.push(body);
        return jsonResponse({ data: { ...EXCEPTIONS_RESPONSE.data[0], status: 'approved', approval_notes: body.approval_notes } });
      }
      return jsonResponse({}, 404);
    });

    const dom = loadPage('exceptions.html', { fetchImplementation: fetchMock });
    const document = dom.window.document;

    await vi.waitFor(() => {
      const approveButton = document.querySelector('[data-exception-body] button.primary');
      expect(approveButton).not.toBeNull();
    });

    const approveButton = document.querySelector('[data-exception-body] button.primary') as HTMLButtonElement;
    approveButton.click();

    await vi.waitFor(() => {
      const modal = document.querySelector('[data-action-modal]');
      expect(modal?.hasAttribute('open')).toBe(true);
    });

    const notesField = document.querySelector('[data-modal-notes]') as HTMLTextAreaElement;
    const submitButton = document.querySelector('[data-modal-submit]') as HTMLButtonElement;

    notesField.value = 'Risk accepted';
    submitButton.click();

    await vi.waitFor(() => {
      expect(putPayloads).toHaveLength(1);
    });
    expect(putPayloads[0]).toMatchObject({
      tenant_id: '55555555-5555-4555-8555-555555555555',
      status: 'approved',
      approval_notes: 'Risk accepted'
    });

    await vi.waitFor(() => {
      const badge = document.querySelector('.badge');
      expect(badge?.textContent).toContain('approved');
    });
  });
});
