import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const baseURL = (__ENV.BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
const routeSlug = __ENV.ROUTE_SLUG || 'openai-main';
const gatewayToken = __ENV.GATEWAY_TOKEN || '';
const model = __ENV.MODEL || 'test-model';
const endpoint = __ENV.ENDPOINT || '/v1/chat/completions';
const expectedMode = (__ENV.EXPECTED_MODE || 'allow').toLowerCase();

const risk555 = new Counter('riskgate_555_total');
const unexpectedResponses = new Rate('riskgate_unexpected_response_rate');
const endToEnd = new Trend('riskgate_end_to_end_ms', true);

export const options = {
  scenarios: {
    steady_gateway_traffic: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 50),
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: Number(__ENV.PREALLOCATED_VUS || 100),
      maxVUs: Number(__ENV.MAX_VUS || 500),
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<2500', 'p(99)<5000'],
    riskgate_unexpected_response_rate: ['rate<0.01'],
  },
  discardResponseBodies: false,
  noConnectionReuse: false,
  userAgent: 'riskgate-k6-safe-load-test/1.0',
};

function requestBody() {
  if (expectedMode === 'block') {
    // This harmless marker must only be paired with a temporary test rule such
    // as (?i)RISK_GATE_BLOCK_TEST; it intentionally contains no harmful content.
    return {
      model,
      stream: false,
      messages: [{ role: 'user', content: 'RISK_GATE_BLOCK_TEST' }],
      max_tokens: 8,
    };
  }
  return {
    model,
    stream: false,
    messages: [{ role: 'user', content: 'Reply with the single word OK.' }],
    max_tokens: 8,
  };
}

export default function () {
  if (!gatewayToken) {
    throw new Error('GATEWAY_TOKEN is required');
  }

  const requestID = `k6-${__VU}-${__ITER}-${Date.now()}`;
  const response = http.post(
    `${baseURL}/gateway/${routeSlug}${endpoint}`,
    JSON.stringify(requestBody()),
    {
      headers: {
        Authorization: `Bearer ${gatewayToken}`,
        'Content-Type': 'application/json',
        'X-Request-ID': requestID,
        'X-NewAPI-Tenant-ID': 'load-test',
        'X-NewAPI-User-ID': `vu-${__VU}`,
      },
      tags: { route_slug: routeSlug, expected_mode: expectedMode },
      timeout: __ENV.REQUEST_TIMEOUT || '30s',
    },
  );

  endToEnd.add(response.timings.duration);
  if (response.status === 555) {
    risk555.add(1);
  }

  const expected = expectedMode === 'block'
    ? response.status === 555
    : response.status >= 200 && response.status < 300;
  unexpectedResponses.add(!expected);

  check(response, {
    'response matches expected mode': () => expected,
    'request id is returned': (res) => Boolean(res.headers['X-Risk-Request-Id'] || res.headers['X-Risk-Request-ID']),
    '555 has standardized code': (res) => {
      if (res.status !== 555) return true;
      try {
        return JSON.parse(res.body).error.code === 555;
      } catch (_) {
        return false;
      }
    },
  });

  if (__ENV.SLEEP_MS) {
    sleep(Number(__ENV.SLEEP_MS) / 1000);
  }
}

export function handleSummary(data) {
  const summary = {
    generated_at: new Date().toISOString(),
    base_url: baseURL,
    route_slug: routeSlug,
    expected_mode: expectedMode,
    metrics: data.metrics,
  };
  return {
    stdout: `\nRiskGate load test finished for ${routeSlug}.\n`,
    'riskgate-k6-summary.json': JSON.stringify(summary, null, 2),
  };
}
