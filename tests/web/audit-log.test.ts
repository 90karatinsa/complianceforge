// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { loadPage } from './utils.ts';

const DEFAULT_EVENTS = [
  {
    id: 'event-1',
    tenant_id: '55555555-5555-4555-8555-555555555555',
    project_id: 'project-1',
    scan_id: 'scan-1',
    actor_type: 'api_key',
    actor_identifier: 'key-01',
    event_type: 'project.created',
    event_payload: { project_id: 'project-1', repo_url: 'https://example.com/repo.git' },
    event_hash: 'hash-1',
    created_at: '2024-07-01T09:00:00.000Z'
  },
  {
    id: 'event-2',
    tenant_id: '55555555-5555-4555-8555-555555555555',
    project_id: null,
    scan_id: 'scan-2',
    actor_type: 'api_key',
    actor_identifier: 'key-02',
    event_type: 'scan.enqueued',
    event_payload: { scan_id: 'scan-2', policy_result: 'pending' },
    event_hash: 'hash-2',
    created_at: '2024-06-30T14:35:00.000Z'
  }
];

const SECOND_PAGE_EVENT = {
  id: 'event-3',
  tenant_id: '55555555-5555-4555-8555-555555555555',
  project_id: 'project-legacy',
  scan_id: null,
  actor_type: 'system',
  actor_identifier: null,
  event_type: 'feed.imported',
  event_payload: { manifest: 'feed-2024.06.25.tgz' },
  event_hash: 'hash-3',
  created_at: '2024-06-28T08:00:00.000Z'
};

const createJsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

const flushAsync = async (window: Window) => {
  await Promise.resolve();
  await new Promise((resolve) => window.setTimeout(resolve, 0));
};

describe('Audit log page', () => {
  it('renders audit events and configures export link', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      createJsonResponse({
        data: DEFAULT_EVENTS,
        pagination: { limit: 25, next_cursor: 'cursor-next' }
      })
    );

    const { window } = await loadPage('audit-log.html', { fetchImplementation: fetchMock });
    await flushAsync(window);
    await flushAsync(window);

    const { document } = window;
    const rows = Array.from(document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-audit-row]'));
    expect(rows).toHaveLength(DEFAULT_EVENTS.length);
    expect(rows[0]?.textContent).toContain('project.created');

    const status = document.querySelector('[data-audit-status]');
    expect(status?.textContent).toContain('2 kayıt');

    const exportLink = document.querySelector<HTMLAnchorElement>('[data-export-link]');
    expect(exportLink?.getAttribute('href')).toContain('/v1/audit/events?');
    expect(exportLink?.getAttribute('href')).toContain('format=jsonl');
    expect(exportLink?.getAttribute('download')).toMatch(/audit-events-/);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('submits filters and requests filtered data', async () => {
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo) => {
      const url = new URL(typeof input === 'string' ? input : (input as Request).url, 'https://atlas.local');

      if (url.searchParams.get('event_type') === 'scan.failed') {
        return Promise.resolve(
          createJsonResponse({
            data: [
              {
                ...SECOND_PAGE_EVENT,
                event_type: 'scan.failed',
                event_payload: { scan_id: 'scan-9', reason: 'policy_fail' }
              }
            ],
            pagination: { limit: 25, next_cursor: null }
          })
        );
      }

      return Promise.resolve(
        createJsonResponse({ data: DEFAULT_EVENTS, pagination: { limit: 25, next_cursor: null } })
      );
    });

    const { window } = await loadPage('audit-log.html', { fetchImplementation: fetchMock });
    await flushAsync(window);
    await flushAsync(window);

    const { document } = window;
    const eventTypeInput = document.querySelector<HTMLInputElement>('#audit-type');
    eventTypeInput!.value = 'scan.failed';

    const form = document.querySelector<HTMLFormElement>('[data-filter-form]');
    form?.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));

    await flushAsync(window);
    await flushAsync(window);

    const lastCall = fetchMock.mock.calls.at(-1)?.[0];
    const lastUrl = new URL(typeof lastCall === 'string' ? lastCall : (lastCall as Request).url, 'https://atlas.local');
    expect(lastUrl.searchParams.get('event_type')).toBe('scan.failed');

    const rows = Array.from(document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-audit-row]'));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.textContent).toContain('scan.failed');
  });

  it('paginates with next and previous controls', async () => {
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo) => {
      const url = new URL(typeof input === 'string' ? input : (input as Request).url, 'https://atlas.local');
      if (url.searchParams.get('cursor') === 'cursor-next') {
        return Promise.resolve(
          createJsonResponse({ data: [SECOND_PAGE_EVENT], pagination: { limit: 25, next_cursor: null } })
        );
      }

      return Promise.resolve(
        createJsonResponse({
          data: [DEFAULT_EVENTS[0]],
          pagination: { limit: 25, next_cursor: 'cursor-next' }
        })
      );
    });

    const { window } = await loadPage('audit-log.html', { fetchImplementation: fetchMock });
    await flushAsync(window);
    await flushAsync(window);

    const { document } = window;
    const nextButton = document.querySelector<HTMLButtonElement>('[data-pagination="next"]');
    const prevButton = document.querySelector<HTMLButtonElement>('[data-pagination="prev"]');
    const indicator = document.querySelector('[data-page-indicator]');

    expect(prevButton?.disabled).toBe(true);
    expect(indicator?.textContent).toContain('Sayfa 1');

    nextButton?.click();
    await flushAsync(window);
    await flushAsync(window);

    const nextRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-audit-row]'));
    expect(nextRows).toHaveLength(1);
    expect(nextRows[0]?.textContent).toContain('feed.imported');
    expect(prevButton?.disabled).toBe(false);
    expect(indicator?.textContent).toContain('Sayfa 2');

    prevButton?.click();
    await flushAsync(window);
    await flushAsync(window);

    const prevRows = Array.from(document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-audit-row]'));
    expect(prevRows).toHaveLength(1);
    expect(prevRows[0]?.textContent).toContain('project.created');
    expect(prevButton?.disabled).toBe(true);
    expect(indicator?.textContent).toContain('Sayfa 1');
  });
});
