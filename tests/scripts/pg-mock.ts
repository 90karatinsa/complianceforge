// SPDX-License-Identifier: MIT

import { vi } from 'vitest';

type MockFn<Args extends readonly unknown[], Return> = ReturnType<typeof vi.fn<Args, Return>>;

interface MockClient {
  readonly query: MockFn<[string], Promise<unknown>>;
  readonly release: MockFn<[], Promise<void>>;
}

export interface MockPool {
  readonly connect: MockFn<[], Promise<MockClient>>;
  readonly end: MockFn<[], Promise<void>>;
  readonly query: MockClient['query'];
  readonly __config: unknown;
  readonly __query: MockClient['query'];
  readonly __release: MockClient['release'];
}

const pools: MockPool[] = [];
let nextQueryImplementation: ((sql: string) => Promise<unknown>) | undefined;

export function mockPgModule() {
  return {
    Pool: vi.fn((config: unknown) => {
      const query = vi.fn<[string], Promise<unknown>>((sql) => {
        if (nextQueryImplementation) {
          return nextQueryImplementation(sql);
        }
        return Promise.resolve(undefined);
      });
      const release = vi.fn<[], Promise<void>>(() => Promise.resolve(undefined));
      const client: MockClient = {
        query,
        release
      };
      const connect = vi.fn<[], Promise<MockClient>>(() => Promise.resolve(client));
      const end = vi.fn<[], Promise<void>>(() => Promise.resolve(undefined));
      const pool: MockPool = {
        connect,
        end,
        query,
        __config: config,
        __query: query,
        __release: release
      };
      pools.push(pool);
      return pool;
    })
  };
}

export function resetPools(): MockPool[] {
  const snapshot = [...pools];
  pools.length = 0;
  return snapshot;
}

export function setNextQueryImplementation(
  implementation: ((sql: string) => Promise<unknown>) | undefined
): void {
  nextQueryImplementation = implementation;
}
