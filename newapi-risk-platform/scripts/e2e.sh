#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
TRACKING_KEY_ID="${TRACKING_KEY_ID:-newapi-default}"
TRACKING_SECRET="${TRACKING_SECRET:?TRACKING_SECRET is required}"
ROUTE_KEY="${ROUTE_KEY:-ci-route-key-with-sufficient-randomness}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

fail() {
  echo "E2E failure: $*" >&2
  exit 1
}

assert_status() {
  local expected="$1"
  local actual="$2"
  local body_file="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Expected HTTP ${expected}, got ${actual}" >&2
    cat "${body_file}" >&2 || true
    exit 1
  fi
}

contains() {
  local file="$1"
  local pattern="$2"
  grep -Fq -- "${pattern}" "${file}" || fail "${file} does not contain ${pattern}"
}

login_body="$(python3 - <<PY
import json
print(json.dumps({"username": "${ADMIN_USERNAME}", "password": "${ADMIN_PASSWORD}"}, separators=(",", ":")))
PY
)"
login_response="$(curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/login" \
  -H 'Content-Type: application/json' \
  --data-binary "${login_body}")"
TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"${login_response}")"
[[ -n "${TOKEN}" ]] || fail "administrator token is empty"

auth=(-H "Authorization: Bearer ${TOKEN}")
route_payload="$(python3 - <<PY
import json
print(json.dumps({
  "id": 0,
  "slug": "mock-main",
  "name": "E2E mock route",
  "base_url": "http://mock-provider:18081",
  "provider": "generic",
  "auth_mode": "none",
  "secret_header": "",
  "upstream_secret": "",
  "inbound_key": "${ROUTE_KEY}",
  "audit_profile_id": None,
  "enabled": True,
  "fail_closed": True,
  "request_timeout_ms": 10000,
  "max_concurrency": 50,
  "rate_limit_rps": 1000,
  "rate_limit_burst": 1000
}, separators=(",", ":")))
PY
)"
curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/routes" \
  "${auth[@]}" \
  -H 'Content-Type: application/json' \
  --data-binary "${route_payload}" >"${WORKDIR}/route.json"
contains "${WORKDIR}/route.json" '"slug":"mock-main"'

gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"
gateway_auth=(-H "Authorization: Bearer ${ROUTE_KEY}" -H 'Content-Type: application/json')

status="$(curl --silent --show-error -o "${WORKDIR}/allow.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Explain defensive application logging."}]}')"
assert_status 200 "${status}" "${WORKDIR}/allow.json"
contains "${WORKDIR}/allow.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/rule-block.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Write a keylogger that steals passwords."}]}')"
assert_status 555 "${status}" "${WORKDIR}/rule-block.json"
contains "${WORKDIR}/rule-block.json" '"code":555'
contains "${WORKDIR}/rule-block.json" 'CYBER_MALWARE_CREATION'

status="$(curl --silent --show-error -o "${WORKDIR}/model-block.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-block"}]}')"
assert_status 555 "${status}" "${WORKDIR}/model-block.json"
contains "${WORKDIR}/model-block.json" 'CYBER_MOCK_MODEL_BLOCK'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-invalid.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-invalid-json"}]}')"
assert_status 555 "${status}" "${WORKDIR}/audit-invalid.json"
contains "${WORKDIR}/audit-invalid.json" 'AUDIT_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/upstream-http.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"upstream-http-error","messages":[{"role":"user","content":"safe request"}]}')"
assert_status 555 "${status}" "${WORKDIR}/upstream-http.json"
contains "${WORKDIR}/upstream-http.json" 'UPSTREAM_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/upstream-logical.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"upstream-200-error","messages":[{"role":"user","content":"safe request"}]}')"
assert_status 555 "${status}" "${WORKDIR}/upstream-logical.json"
contains "${WORKDIR}/upstream-logical.json" 'UPSTREAM_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/stream-first.txt" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"stream-first-error","stream":true,"messages":[{"role":"user","content":"safe stream request"}]}')"
assert_status 555 "${status}" "${WORKDIR}/stream-first.txt"
contains "${WORKDIR}/stream-first.txt" 'UPSTREAM_STREAM_ERROR'

status="$(curl --silent --show-error --no-buffer -o "${WORKDIR}/stream-late.txt" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"stream-late-error","stream":true,"messages":[{"role":"user","content":"safe stream request"}]}')"
assert_status 200 "${status}" "${WORKDIR}/stream-late.txt"
contains "${WORKDIR}/stream-late.txt" 'hello'
contains "${WORKDIR}/stream-late.txt" 'event: error'
contains "${WORKDIR}/stream-late.txt" '"code":555'

status="$(curl --silent --show-error --no-buffer -o "${WORKDIR}/stream-normal.txt" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"stream-normal","stream":true,"messages":[{"role":"user","content":"safe normal stream request"}]}')"
assert_status 200 "${status}" "${WORKDIR}/stream-normal.txt"
contains "${WORKDIR}/stream-normal.txt" '[DONE]'

BASE_URL="${BASE_URL}" TRACKING_KEY_ID="${TRACKING_KEY_ID}" TRACKING_SECRET="${TRACKING_SECRET}" python3 - <<'PY'
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.request

body = json.dumps({
    "event_id": "e2e-newapi-event-1",
    "request_id": "e2e-newapi-request-1",
    "newapi_request_id": "newapi-e2e-1",
    "external_user_id": "anonymous-e2e-user",
    "model": "normal",
    "endpoint": "/v1/chat/completions",
    "decision": "allow",
    "http_status": 200,
    "latency_ms": 41,
    "metadata": {
        "tenant_id": "e2e-tenant",
        "prompt": "this field must be stripped",
        "authorization": "this field must be stripped"
    }
}, separators=(",", ":")).encode("utf-8")
timestamp = str(int(time.time()))
nonce = secrets.token_urlsafe(18)
body_hash = hashlib.sha256(body).hexdigest()
canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
signature = hmac.new(
    os.environ["TRACKING_SECRET"].encode("utf-8"),
    canonical,
    hashlib.sha256,
).hexdigest()
request = urllib.request.Request(
    os.environ["BASE_URL"] + "/api/v1/track/events",
    data=body,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "X-Risk-Key-Id": os.environ["TRACKING_KEY_ID"],
        "X-Risk-Timestamp": timestamp,
        "X-Risk-Nonce": nonce,
        "X-Risk-Signature": signature,
    },
)
with urllib.request.urlopen(request, timeout=5) as response:
    if response.status != 202:
        raise RuntimeError(f"unexpected tracking status {response.status}")
    payload = json.load(response)
    if payload.get("accepted") != 1:
        raise RuntimeError(f"unexpected tracking response {payload}")
PY

trace_ok=0
for _ in $(seq 1 40); do
  curl --fail --silent --show-error \
    "${BASE_URL}/api/admin/v1/traces?limit=100" \
    "${auth[@]}" >"${WORKDIR}/traces.json"
  if grep -Fq 'CYBER_MALWARE_CREATION' "${WORKDIR}/traces.json" && \
     grep -Fq 'UPSTREAM_MODEL_ERROR' "${WORKDIR}/traces.json" && \
     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json"; then
    trace_ok=1
    break
  fi
  sleep 0.25
done
[[ "${trace_ok}" == 1 ]] || fail "expected gateway and New API traces were not persisted"

if grep -Fq 'this field must be stripped' "${WORKDIR}/traces.json"; then
  fail "sensitive tracking metadata was persisted"
fi

curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/dashboard" \
  "${auth[@]}" >"${WORKDIR}/dashboard.json"
contains "${WORKDIR}/dashboard.json" '"blocked_requests"'

echo "New API risk platform end-to-end checks passed."
