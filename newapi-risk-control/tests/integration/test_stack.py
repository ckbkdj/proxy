#!/usr/bin/env python3
"""Exercise a running local RiskGate stack using only the standard library."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

BASE_URL = os.environ.get("RISKGATE_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
ADMIN_PASSWORD = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "ChangeThisPasswordNow!123")
TRACE_SECRET = os.environ.get("TRACE_HMAC_SECRET", "change-me-to-at-least-32-random-bytes")


def request(
    path: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    allow_error: bool = False,
) -> tuple[int, dict[str, str], bytes]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request_headers = {"Accept": "application/json"}
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers=request_headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        raw = error.read()
        if not allow_error:
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {raw!r}") from error
        return error.code, dict(error.headers), raw


def decode(raw: bytes) -> dict[str, Any]:
    return json.loads(raw.decode("utf-8"))


def wait_ready() -> None:
    for _ in range(90):
        try:
            status, _, _ = request("/readyz")
            if status == 200:
                return
        except (OSError, RuntimeError):
            pass
        time.sleep(1)
    raise RuntimeError("RiskGate never became ready")


def gateway(token: str, payload: dict[str, Any]) -> tuple[int, dict[str, str], bytes]:
    return request(
        "/gateway/integration/v1/chat/completions",
        "POST",
        payload,
        headers={
            "Authorization": f"Bearer {token}",
            "X-Request-ID": f"integration-{secrets.token_hex(6)}",
            "X-NewAPI-Tenant-ID": "tenant-integration",
            "X-NewAPI-User-ID": "user-integration",
        },
        allow_error=True,
    )


def main() -> int:
    wait_ready()

    status, _, raw = request(
        "/admin/api/v1/login",
        "POST",
        {"username": "admin", "password": ADMIN_PASSWORD},
    )
    assert status == 200
    admin_token = decode(raw)["token"]

    status, _, raw = request(
        "/admin/api/v1/audit-profiles",
        "POST",
        {
            "name": "integration-audit",
            "endpoint": "http://riskgate-mock:9000/v1",
            "model": "audit-small",
            "api_key": "audit-key",
            "enabled": True,
            "fail_mode": "closed",
            "block_threshold": 0.72,
            "timeout_ms": 5000,
            "max_input_chars": 32000,
            "cache_ttl_seconds": 0,
            "system_prompt": "",
        },
        admin_token,
    )
    assert status == 201, raw
    audit_id = decode(raw)["id"]

    status, _, raw = request(
        "/admin/api/v1/rules",
        "POST",
        {
            "name": "integration-safe-marker",
            "category": "integration_test",
            "pattern": "(?i)RISK_GATE_BLOCK_TEST",
            "action": "block",
            "score": 1,
            "priority": 2000,
            "enabled": True,
        },
        admin_token,
    )
    assert status == 201, raw

    status, _, raw = request(
        "/admin/api/v1/routes",
        "POST",
        {
            "name": "Integration Route",
            "slug": "integration",
            "upstream_base_url": "http://riskgate-mock:9000",
            "upstream_kind": "openai",
            "upstream_api_key": "provider-key",
            "client_token": "",
            "audit_profile_id": audit_id,
            "enabled": True,
            "rate_limit_rps": 1000,
            "rate_limit_burst": 2000,
            "max_inflight": 100,
            "request_timeout_ms": 30000,
            "allow_private_upstream": True,
        },
        admin_token,
    )
    assert status == 201, raw
    route = decode(raw)
    gateway_token = route["client_token"]
    assert gateway_token and route["newapi_base_url"].endswith("/gateway/integration")

    status, headers, raw = gateway(
        gateway_token,
        {
            "model": "normal-model",
            "stream": False,
            "messages": [{"role": "user", "content": "Reply OK"}],
        },
    )
    assert status == 200 and decode(raw)["choices"][0]["message"]["content"] == "OK"
    assert headers.get("X-Risk-Request-Id") or headers.get("X-Risk-Request-ID")

    status, _, raw = gateway(
        gateway_token,
        {
            "model": "normal-model",
            "stream": False,
            "messages": [{"role": "user", "content": "RISK_GATE_BLOCK_TEST"}],
        },
    )
    assert status == 555 and decode(raw)["error"]["code"] == 555

    status, _, raw = gateway(
        gateway_token,
        {
            "model": "normal-model",
            "stream": False,
            "messages": [{"role": "user", "content": "MODEL_BLOCK_TEST"}],
        },
    )
    assert status == 555 and decode(raw)["error"]["code"] == 555

    status, _, raw = gateway(
        gateway_token,
        {
            "model": "missing-model",
            "stream": False,
            "messages": [{"role": "user", "content": "Use a missing model"}],
        },
    )
    assert status == 555 and decode(raw)["error"]["code"] == 555

    status, _, raw = gateway(
        gateway_token,
        {
            "model": "bad-request",
            "stream": False,
            "messages": [{"role": "user", "content": "Send a normal invalid request"}],
        },
    )
    assert status == 400 and decode(raw)["error"]["code"] == "invalid_request_error"

    status, _, raw = gateway(
        gateway_token,
        {
            "model": "stream-error-first",
            "stream": True,
            "messages": [{"role": "user", "content": "Start stream"}],
        },
    )
    assert status == 555 and decode(raw)["error"]["code"] == 555

    status, _, raw = gateway(
        gateway_token,
        {
            "model": "stream-error-late",
            "stream": True,
            "messages": [{"role": "user", "content": "Start stream"}],
        },
    )
    stream = raw.decode("utf-8")
    assert status == 200
    assert "hello" in stream and '"code":555' in stream and "event: error" in stream

    trace = {
        "external_request_id": "newapi-integration-trace",
        "route_slug": "integration",
        "tenant_id": "tenant-integration",
        "user_id": "user-plain",
        "api_key_fingerprint": "key-plain",
        "model": "normal-model",
        "provider": "openai",
        "method": "POST",
        "path": "/v1/chat/completions",
        "http_status": 200,
        "outcome": "newapi_completed",
        "metadata": {
            "region": "test",
            "prompt": "must-be-removed",
            "authorization": "must-be-removed",
        },
    }
    body = json.dumps(trace, separators=(",", ":")).encode("utf-8")
    timestamp = int(time.time())
    nonce = secrets.token_urlsafe(24)
    digest = hashlib.sha256(body).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{digest}".encode("utf-8")
    signature = hmac.new(
        TRACE_SECRET.encode("utf-8"), canonical, hashlib.sha256
    ).hexdigest()
    signed_request = urllib.request.Request(
        BASE_URL + "/api/v1/traces/ingest",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Risk-Timestamp": str(timestamp),
            "X-Risk-Nonce": nonce,
            "X-Risk-Key-ID": "newapi",
            "X-Risk-Signature": signature,
        },
    )
    with urllib.request.urlopen(signed_request, timeout=20) as response:
        assert response.status == 202
        assert json.loads(response.read())["accepted"] == 1

    found: dict[str, Any] | None = None
    for _ in range(50):
        _, _, raw = request(
            "/admin/api/v1/traces?request_id="
            + urllib.parse.quote("newapi-integration-trace"),
            token=admin_token,
        )
        items = decode(raw)["items"]
        if items:
            found = items[0]
            break
        time.sleep(0.2)
    assert found is not None
    assert found["metadata"].get("region") == "test"
    assert "prompt" not in found["metadata"]
    assert "authorization" not in found["metadata"]
    assert found["user_id_hash"] and found["user_id_hash"] != "user-plain"
    assert found["api_key_hash"] and found["api_key_hash"] != "key-plain"

    status, _, raw = request("/admin/api/v1/storage-policy", token=admin_token)
    policy = decode(raw)
    assert status == 200
    assert policy["retention_days"] == 7 and policy["store_raw_prompt"] is False

    print(
        json.dumps(
            {
                "ok": True,
                "checks": [
                    "ready",
                    "login",
                    "profile",
                    "rule",
                    "route",
                    "allow",
                    "rule_555",
                    "model_555",
                    "upstream_555",
                    "pass_400",
                    "sse_precommit_555",
                    "sse_postcommit_555",
                    "trace_hmac",
                    "metadata_redaction",
                    "retention_7d",
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"integration assertion failed: {error}", file=sys.stderr)
        raise
