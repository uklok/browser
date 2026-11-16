#!/usr/bin/env python3
"""Measure a live reading-honeypot capture. Not part of the fixture gate."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "automations" / "_runtime"))
import operations  # noqa: E402


def load_events(run: Path) -> list[dict]:
    path = run / "traffic" / "events.jsonl"
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def derived_text(run: Path) -> str:
    files = []
    if (run / "operations").exists():
        files.extend((run / "operations").rglob("*.json"))
    if (run / "steps").exists():
        for directory in (run / "steps").glob("*/operations"):
            files.extend(directory.rglob("*.json"))
    return "\n".join(path.read_text(encoding="utf-8") for path in files)


def redirect_trace(events: list[dict]) -> list[dict]:
    trace = []
    for event in events:
        raw = event.get("cdp") or {}
        method = raw.get("method")
        params = raw.get("params") or {}
        request = params.get("request") or {}
        url = str(request.get("url") or (params.get("response") or {}).get("url") or "")
        if "reading.test" not in url and method not in {
            "Network.requestWillBeSent",
            "Network.responseReceived",
            "Network.responseReceivedExtraInfo",
            "Network.requestWillBeSentExtraInfo",
        }:
            continue
        if "redirect" not in url and method != "Network.responseReceivedExtraInfo":
            if "redirect" not in url:
                continue
        trace.append(
            {
                "seq": event.get("seq"),
                "method": method,
                "http": request.get("method"),
                "url": url,
                "status": (params.get("response") or {}).get("status") or params.get("statusCode"),
                "redirect_has_extra": params.get("redirectHasExtraInfo"),
                "cookie": (request.get("headers") or {}).get("Cookie")
                or ((params.get("response") or {}).get("headers") or {}).get("Set-Cookie")
                or (params.get("headers") or {}).get("Set-Cookie"),
            }
        )
    return trace


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: reading-honeypot-live.py <run-dir>", file=sys.stderr)
        return 2
    run = Path(sys.argv[1]).resolve()
    events = load_events(run)
    cdp_methods = sorted({(event.get("cdp") or {}).get("method") for event in events if event.get("cdp")})
    print(json.dumps({"cdp_methods": cdp_methods, "event_count": len(events), "redirect_trace": redirect_trace(events)}, indent=2))
    try:
        index = operations.derive_operations(run)
    except operations.OperationReadError as exc:
        published = (run / "operations").exists()
        print(json.dumps({"derive": "failed", "error": str(exc), "published": published}, indent=2))
        return 0 if (not published and "secret survived" in str(exc)) else 1

    text = derived_text(run)
    endpoints = []
    for path in (run / "steps").glob("*/operations/endpoints.json"):
        endpoints.extend(json.loads(path.read_text())["operations"])
    by_key = {item["key"]: item for item in endpoints}
    report = {
        "derive": "published",
        "keys": index["operation_keys"],
        "reconciles": index["integrity"]["reconciles"],
        "steps": {step: value.get("artifact_status") for step, value in index["steps"].items()},
        "secret_in_derived": "live-hop-secret" in text or "NonsensitiveOpaqueValue" in text,
        "opaque_literal_in_derived": "jStkcFiTKsVzcqdhcpWMPdYC" in text,
        "acknowledgements_key": [key for key in index["operation_keys"] if "acknowledgements" in key],
        "profile_key": [key for key in index["operation_keys"] if "GetCurrentUserProfile" in key],
        "challenge_keys": [key for key in index["operation_keys"] if "challenge" in key],
        "graphql_keys": [key for key in index["operation_keys"] if key.startswith("graphql|")],
        "redirect": {
            key: {
                "method": item["method"],
                "host": item["host"],
                "path": item["path"],
                "dependencies": item["credential_dependencies"],
                "cookies": item["response"]["sets_cookies"],
                "provenance": item["provenance"],
            }
            for key, item in by_key.items()
            if "redirect" in key
        },
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
