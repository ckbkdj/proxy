import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const baseURL = (__ENV.BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
const routeSlug = __ENV.ROUTE_SLUG || 'openai-main';
const gatewayKey = __ENV.GATEWAY_KEY || '';
const model = __ENV.MODEL || 'test-model';
const targetRPS = Number(__ENV.TARGET_RPS || 100);
const duration = __ENV.DURATION || '2m';
const preAllocatedVUs = Number(__ENV.PRE_ALLOCATED_VUS || Math.max(50, targetRPS));
const maxVUs = Number(__ENV.MAX_VUS || Math.max(200, targetRPS * 4));

const risk555 = new Counter('risk_555_total');
const successful = new Rate('gateway_success_rate');
const applicationLatency = new Trend('gateway_application_latency_ms', true);

export const options = {
  discardResponseBodies: false,
  scenarios: {
    gateway: {
      executor: 'constant-arrival-rate',
      rate: targetRPS,
      timeUnit: '1s',
      duration,
      preAllocatedVUs,
      maxVUs,
      gracefulStop: '30s',
    },
  },
  thresholds: {
    gateway_success_rate: ['rate>0.995'],
    http_req_duration: ['p(95)<3000', 'p(99)<8000'],
    http_req_failed: ['rate<0.005'],
    dropped_iterations: ['count==0'],
  },
};

export function setup() {
  if (!gatewayKey) {
    throw new Error('GATEWAY_KEY is required');
  }
}

export default function () {
  const requestID = `k6-${__VU}-${__ITER}-${Date.now()}`;
  const payload = JSON.stringify({
    model,
    stream: false,
    messages: [
      {
        role: 'user',
        content: 'Summarize defensive application logging practices in three short points.',
      },
    ],
  });
  const response = http.post(
    `${baseURL}/gateway/${encodeURIComponent(routeSlug)}/v1/chat/completions`,
    payload,
    {
      headers: {
        Authorization: `Bearer ${gatewayKey}`,
        'Content-Type': 'application/json',
        'X-Request-ID': requestID,
        'X-NewAPI-Request-ID': requestID,
        'X-NewAPI-User-ID': `load-user-${__VU % 1000}`,
      },
      tags: {
        route: routeSlug,
        model,
      },
      timeout: __ENV.REQUEST_TIMEOUT || '30s',
    },
  );

  if (response.status === 555) {
    risk555.add(1);
  }
  const passed = check(response, {
    'gateway returns HTTP 200': (result) => result.status === 200,
    'response is not a risk error': (result) => !result.body?.includes('risk_control_error'),
    'request ID is returned': (result) => Boolean(result.headers['X-Risk-Request-Id']),
  });
  successful.add(passed);
  applicationLatency.add(response.timings.duration);

  if (__ENV.THINK_TIME_MS) {
    sleep(Number(__ENV.THINK_TIME_MS) / 1000);
  }
}
