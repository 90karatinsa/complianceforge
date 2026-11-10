// SPDX-License-Identifier: MIT

const ALLOW_NETWORK_FETCH_ENV = 'ALLOW_NETWORK_FETCH';

export function isNetworkFetchAllowed(): boolean {
  const value = process.env[ALLOW_NETWORK_FETCH_ENV];

  if (typeof value !== 'string') {
    return false;
  }

  const normalized = value.trim().toLowerCase();

  if (normalized === '') {
    return false;
  }

  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

export function assertNetworkFetchAllowed(context: string): void {
  if (isNetworkFetchAllowed()) {
    return;
  }

  throw new Error(`Network fetches are disabled by ${ALLOW_NETWORK_FETCH_ENV} for ${context}.`);
}
