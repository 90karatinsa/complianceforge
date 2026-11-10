// SPDX-License-Identifier: MIT

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { JSDOM } from 'jsdom';

interface LoadOptions {
  matchMedia?: (query: string) => boolean;
  localStorage?: Record<string, string>;
  fetchImplementation?: typeof fetch;
}

function createMatchMedia(
  _window: Window,
  matcher?: (query: string) => boolean
): (query: string) => MediaQueryList {
  return (query: string) => {
    const matches = typeof matcher === 'function' ? matcher(query) : query.includes('dark');
    const listeners = new Set<(event: MediaQueryListEvent) => void>();

    const mediaQueryList: MediaQueryList = {
      matches,
      media: query,
      onchange: null,
      addEventListener: (_type: string, listener: EventListenerOrEventListenerObject) => {
        if (typeof listener === 'function') {
          listeners.add(listener as (event: MediaQueryListEvent) => void);
        }
      },
      removeEventListener: (_type: string, listener: EventListenerOrEventListenerObject) => {
        if (typeof listener === 'function') {
          listeners.delete(listener as (event: MediaQueryListEvent) => void);
        }
      },
      addListener: (listener: (event: MediaQueryListEvent) => void) => {
        listeners.add(listener);
      },
      removeListener: (listener: (event: MediaQueryListEvent) => void) => {
        listeners.delete(listener);
      },
      dispatchEvent: () => false
    };

    return mediaQueryList;
  };
}

export function loadPage(path: string, options: LoadOptions = {}) {
  const filePath = resolve('web', path);
  const html = readFileSync(filePath, 'utf8');
  const dom = new JSDOM(html, {
    url: 'https://atlas.local/',
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
    beforeParse(window) {
      window.matchMedia = createMatchMedia(window, options.matchMedia) as typeof window.matchMedia;

      if (options.localStorage) {
        for (const [key, value] of Object.entries(options.localStorage)) {
          window.localStorage.setItem(key, value);
        }
      }

      if (options.fetchImplementation) {
        window.fetch = options.fetchImplementation as typeof window.fetch;
      }
    }
  });

  return dom;
}
