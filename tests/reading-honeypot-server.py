#!/usr/bin/env python3
from __future__ import annotations

import http.client
import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "honeypot"))

import server as honeypot  # noqa: E402


httpd = honeypot.ThreadingHTTPServer(("127.0.0.1", 0), honeypot.Handler)
thread = threading.Thread(target=httpd.serve_forever, daemon=True)
thread.start()
host, port = httpd.server_address


def request(method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
    connection = http.client.HTTPConnection(host, port, timeout=3)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


try:
    status, headers, body = request("GET", "/health")
    assert status == 200
    assert b"<title>reading honeypot</title>" in body
    assert headers["Cache-Control"] == "no-store"

    status, headers, _ = request(
        "POST",
        "/redirect/start",
        body=b'{"amount":5}',
        headers={"Content-Type": "application/json", "Authorization": "Bearer synthetic"},
    )
    assert status == 302
    assert headers["Location"] == "http://b.reading.test/redirect/final"
    assert headers["Set-Cookie"].startswith("intermediate=")

    status, headers, body = request("GET", "/redirect/final")
    assert status == 200
    assert headers["Set-Cookie"].startswith("finalcookie=")
    assert json.loads(body) == {"ok": True, "hop": "final"}

    batch = json.dumps([
        {"query": "query A { a }"},
        {"query": "query B { b }"},
    ]).encode()
    status, _, body = request(
        "POST",
        "/graphql",
        body=batch,
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    payload = json.loads(body)
    assert isinstance(payload, list) and len(payload) == 2
    assert set(payload[0]) == {"data"}
    assert set(payload[1]) == {"errors"}

    status, headers, _ = request("OPTIONS", "/graphql")
    assert status == 204
    assert "authorization" in headers["Access-Control-Allow-Headers"]
    assert "POST" in headers["Access-Control-Allow-Methods"]

    status, _, body = request(
        "POST",
        "/items",
        body=b'{"name":"ordinary"}',
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    assert "Authorization" in json.loads(body)
finally:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=3)

print("reading honeypot server validation passed")
