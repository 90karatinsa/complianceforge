// SPDX-License-Identifier: MIT
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL ?? 'http://localhost:3000';
const API_TOKEN = __ENV.API_TOKEN ?? 'alterra-demo-api-token';
const PROJECT_ID = __ENV.PROJECT_ID ?? 'prj_demo';

export const options = {
  scenarios: {
    smoke: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS ?? 10),
      duration: __ENV.DURATION ?? '1m'
    }
  },
  thresholds: {
    http_req_duration: ['p(95)<250'],
    http_req_failed: ['rate<0.005']
  }
};

const authHeaders = () => ({
  headers: {
    Authorization: `Bearer ${API_TOKEN}`,
    'Content-Type': 'application/json'
  }
});

export default function () {
  const healthRes = http.get(`${BASE_URL}/v1/health`, authHeaders());
  check(healthRes, {
    'health 200': (res) => res.status === 200,
    'health status present': (res) => !!res.json('status')
  });

  const scansRes = http.get(
    `${BASE_URL}/v1/scans?project_id=${PROJECT_ID}&page=1&page_size=5`,
    authHeaders()
  );
  check(scansRes, {
    'scans 200/304': (res) => res.status === 200 || res.status === 304,
    'scans payload array': (res) => Array.isArray(res.json('items') ?? res.json('data') ?? [])
  });

  sleep(1);
}
