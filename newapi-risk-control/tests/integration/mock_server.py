#!/usr/bin/env python3
"""OpenAI-compatible mock used only by the local RiskGate integration test."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RiskGateMock/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(fmt % args, flush=True)

    def send_json(self, status: int, value: object) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802
        self.send_json(200, {"ok": True, "path": self.path})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": {"code": "invalid_json"}})
            return

        messages = payload.get("messages") or []
        system = "\n".join(
            str(message.get("content", ""))
            for message in messages
            if message.get("role") == "system"
        )
        user = "\n".join(
            str(message.get("content", ""))
            for message in messages
            if message.get("role") == "user"
        )

        # The same endpoint acts as the configurable small audit model.
        if "security policy classifier" in system.lower() or payload.get("model") == "audit-small":
            if "MODEL_BLOCK_TEST" in user:
                decision = {
                    "action": "block",
                    "category": "test_policy",
                    "score": 0.99,
                    "reason_code": "MODEL_TEST_BLOCK",
                    "labels": ["integration-test"],
                }
            else:
                decision = {
                    "action": "allow",
                    "category": "benign",
                    "score": 0.01,
                    "reason_code": "MODEL_TEST_ALLOW",
                    "labels": [],
                }
            self.send_json(
                200,
                {"choices": [{"message": {"content": json.dumps(decision)}}]},
            )
            return

        model = payload.get("model", "")
        if model == "missing-model":
            self.send_json(
                400,
                {
                    "error": {
                        "message": "The requested model was not found",
                        "type": "invalid_request_error",
                        "code": "model_not_found",
                    }
                },
            )
            return
        if model == "bad-request":
            self.send_json(
                400,
                {
                    "error": {
                        "message": "A regular invalid parameter",
                        "type": "invalid_request_error",
                        "code": "invalid_request_error",
                    }
                },
            )
            return

        if payload.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            if model == "stream-error-first":
                self.wfile.write(
                    b'event: error\ndata: {"error":{"code":"overloaded_error"}}\n\n'
                )
            elif model == "stream-error-late":
                self.wfile.write(
                    b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
                )
                self.wfile.flush()
                self.wfile.write(
                    b'event: error\ndata: {"error":{"code":"upstream_unavailable"}}\n\n'
                )
            else:
                self.wfile.write(
                    b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n'
                    b'data: [DONE]\n\n'
                )
            self.wfile.flush()
            self.close_connection = True
            return

        self.send_json(
            200,
            {
                "id": "chatcmpl-integration",
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "OK"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()


if __name__ == "__main__":
    main()
