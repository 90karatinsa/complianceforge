// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { createTicketingDispatcher, type TicketingEvent } from '../worker/src/integrations/ticketing.ts';

describe('ticketing dispatcher', () => {
  it('rejects destinations that are not HTTPS', () => {
    expect(() =>
      createTicketingDispatcher(
        [
          {
            type: 'jira',
            url: 'http://jira.example.com',
            email: 'alerts@example.com',
            apiToken: 'token',
            projectKey: 'SCA',
            issueTypeId: '10001'
          }
        ],
        { fetch: vi.fn(), wait: async () => {}, maxAttempts: 1 }
      )
    ).toThrow(/HTTPS/);

    expect(() =>
      createTicketingDispatcher(
        [
          {
            type: 'servicenow',
            url: 'not-a-url',
            username: 'svc_atlas',
            password: 'token',
            table: 'incident'
          }
        ],
        { fetch: vi.fn(), wait: async () => {}, maxAttempts: 1 }
      )
    ).toThrow(/valid HTTPS URL/);
  });

  it('creates Jira and ServiceNow tickets with idempotency headers', async () => {
    const fetchMock = vi
      .fn<Promise<Response>, Parameters<typeof fetch>>()
      .mockResolvedValue({ ok: true, status: 201 } as unknown as Response);

    const dispatcher = createTicketingDispatcher(
      [
        {
          type: 'jira',
          url: 'https://jira.example.com',
          email: 'alerts@example.com',
          apiToken: 'jira-token',
          projectKey: 'SCA',
          issueTypeId: '10001'
        },
        {
          type: 'servicenow',
          url: 'https://sn.example.com',
          username: 'svc_atlas',
          password: 'servicenow-token',
          table: 'incident',
          assignmentGroup: 'AppSec'
        }
      ],
      { fetch: fetchMock, wait: async () => {}, maxAttempts: 1 }
    );

    const event: TicketingEvent = {
      action: 'open',
      tenantId: 'tenant-1',
      projectId: 'project-1',
      scanId: 'scan-123',
      summary: 'Policy failure detected',
      description: 'Atlas SCA blocked an upload due to policy failure.',
      severity: 'high',
      reasons: ['disallowed_license'],
      idempotencyKey: 'ticket-scan-123',
      referenceId: 'project-1',
      link: 'https://atlas.local/scans/scan-123'
    };

    await dispatcher.sync(event);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [jiraCall, snowCall] = fetchMock.mock.calls;
    const jiraRequest = jiraCall?.[1] as { headers?: Record<string, string>; body?: string } | undefined;
    const snowRequest = snowCall?.[1] as { headers?: Record<string, string>; body?: string } | undefined;

    expect(jiraRequest?.headers?.['Idempotency-Key']).toBe('ticket-scan-123');
    expect(jiraRequest?.headers?.Authorization).toMatch(/^Basic /u);
    const jiraBody = jiraRequest?.body ? JSON.parse(jiraRequest.body) : null;
    expect(jiraBody?.fields?.project?.key).toBe('SCA');
    expect(jiraBody?.fields?.policy_reasons).toEqual(['disallowed_license']);
    expect(jiraBody?.fields?.reference_link).toBe(event.link);

    expect(snowRequest?.headers?.['Idempotency-Key']).toBe('ticket-scan-123');
    expect(snowRequest?.headers?.Authorization).toMatch(/^Basic /u);
    const snowBody = snowRequest?.body ? JSON.parse(snowRequest.body) : null;
    expect(snowBody?.short_description).toContain('Policy failure');
    expect(snowBody?.assignment_group).toBe('AppSec');
    expect(snowBody?.u_reference_id).toBe('project-1');
  });

  it('issues resolution requests with mapped endpoints', async () => {
    const fetchMock = vi
      .fn<Promise<Response>, Parameters<typeof fetch>>()
      .mockResolvedValue({ ok: true, status: 200 } as unknown as Response);

    const dispatcher = createTicketingDispatcher(
      [
        {
          type: 'jira',
          url: 'https://jira.example.com/',
          email: 'alerts@example.com',
          apiToken: 'jira-token',
          projectKey: 'SCA',
          issueTypeId: '10001',
          transitionId: '42'
        },
        {
          type: 'servicenow',
          url: 'https://sn.example.com/',
          username: 'svc_atlas',
          password: 'servicenow-token',
          table: 'incident',
          stateField: 'state',
          stateValues: { open: '1', resolved: '8' }
        }
      ],
      { fetch: fetchMock, wait: async () => {}, maxAttempts: 1 }
    );

    const event: TicketingEvent = {
      action: 'resolve',
      tenantId: 'tenant-1',
      projectId: 'project-1',
      scanId: 'scan-555',
      summary: 'Policy restored',
      description: 'Atlas SCA policy status is now pass.',
      severity: 'medium',
      reasons: ['policy_pass'],
      idempotencyKey: 'ticket-scan-555',
      referenceId: 'ticket-123'
    };

    await dispatcher.sync(event);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [jiraCall, snowCall] = fetchMock.mock.calls;
    expect(jiraCall?.[0]).toBe('https://jira.example.com/rest/api/3/issue/ticket-123/transitions');
    expect(snowCall?.[0]).toContain('sysparm_query=u_reference_id%3Dticket-123');
    const jiraBody = jiraCall?.[1] && (jiraCall[1] as { body?: string }).body;
    expect(jiraBody && JSON.parse(jiraBody).transition.id).toBe('42');
    const snowBody = snowCall?.[1] && (snowCall[1] as { body?: string }).body;
    expect(snowBody && JSON.parse(snowBody).state).toBe('8');
  });

  it('sanitizes destination URLs in failure messages', async () => {
    const fetchMock = vi
      .fn<Promise<Response>, Parameters<typeof fetch>>()
      .mockResolvedValue({ ok: false, status: 500 } as unknown as Response);

    const dispatcher = createTicketingDispatcher(
      [
        {
          type: 'jira',
          url: 'https://user:secret@jira.example.com/path?token=abc',
          email: 'alerts@example.com',
          apiToken: 'jira-token',
          projectKey: 'SCA',
          issueTypeId: '10001'
        }
      ],
      { fetch: fetchMock, wait: async () => {}, maxAttempts: 1 }
    );

    const event: TicketingEvent = {
      action: 'open',
      tenantId: 'tenant-1',
      projectId: 'project-1',
      scanId: 'scan-123',
      summary: 'Policy failure detected',
      description: 'Atlas SCA blocked an upload due to policy failure.',
      severity: 'high',
      reasons: ['disallowed_license'],
      idempotencyKey: 'ticket-scan-123',
      referenceId: 'project-1'
    };

    let caughtError: Error | null = null;
    await dispatcher.sync(event).catch((error: Error) => {
      caughtError = error;
    });

    expect(caughtError).toBeInstanceOf(Error);
    expect(caughtError?.message).toMatch(/jira:https:\/\/jira\.example\.com/);
    expect(caughtError?.message).not.toContain('secret');
    expect(caughtError?.message).not.toContain('token=abc');
  });
});
