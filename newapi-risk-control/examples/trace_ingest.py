#!/usr/bin/env python3
"""Send one signed trace event to RiskGate using only the Python standard library."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request


def main() -> int:
    base_url = os.environ.get("RISKGATE_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
    secret = os.environ.get("TRACE_HMAC_SECRET", "")
    if not secret:
        print("TRACE_HMAC_SECRET is required", file=sys.stderr)
        return 2

    event = {
        "external_request_id": "req-demo-001",
        "route_slug": "openai-main",
        "tenant_id": "tenant-demo",
        "user_id": "user-demo",
        "api_key_fingerprint": "newapi-key-demo",
        "model": "gpt-example",
        "provider": "openai",
        "method": "POST",
        "path": "/v1/chat/completions",
        "http_status": 200,
        "outcome": "newapi_completed",
        "metadata": {"billing_units": 128, "region": "us-east"},
    }
    body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = int(time.time())
    nonce = secrets.token_urlsafe(24)
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    request = urllib.request.Request(
        f"{base_url}/api/v1/traces/ingest",
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
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(response.status, response.read().decode("utf-8"))
            return 0
    except urllib.error.HTTPError as error:
        print(error.code, error.read().decode("utf-8", errors="replace"), file=sys.stderr)
        return 1
    except OSError as error:
        print(f"request failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
