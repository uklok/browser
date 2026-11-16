#!/usr/bin/env python3
"""Origins the browser container can reach for live operation-reading capture.

Chrome drives every scenario. This process only answers those requests.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_OPTIONS(self) -> None:
        self._send(204, b"", "text/plain")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            body = b"<html><head><title>reading honeypot</title></head><body>ok</body></html>"
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/redirect/final":
            self._send(200, _json({"ok": True, "hop": "final"}), "application/json", {"Set-Cookie": "finalcookie=kept; Path=/"})
            return
        if path in {"/acknowledgements", "/GetCurrentUserProfile", "/case", "/default"} or path.startswith("/challenge/") or path.startswith("/bucket/"):
            self._send(200, _json({"path": path}), "application/json")
            return
        if path == "/graphql":
            self._send(200, _json({"data": {"thing": {"id": "live"}}}), "application/json")
            return
        self._send(404, _json({"error": "not found"}), "application/json")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or "0")
        if length:
            self.rfile.read(length)
        if path == "/redirect/start":
            self._send(
                302,
                b"",
                "text/plain",
                {
                    "Location": "http://b.reading.test/redirect/final",
                    "Set-Cookie": "intermediate=stale; Path=/",
                },
            )
            return
        if path == "/items":
            self._send(200, _json({"Authorization": "published-field-value", "ok": True}), "application/json")
            return
        if path == "/graphql":
            self._send(200, _json({"data": {"thing": {"id": "live"}}}), "application/json")
            return
        self._send(404, _json({"error": "not found"}), "application/json")

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "authorization, content-type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print("%s %s" % (self.address_string(), fmt % args), flush=True)


def _json(value: dict) -> bytes:
    return json.dumps(value).encode()


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    print("reading honeypot listening on :80", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
