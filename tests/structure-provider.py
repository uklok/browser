#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "automations" / "_runtime"
sys.path.insert(0, str(RUNTIME))

from structure_provider import (  # noqa: E402
    HAR_UNREPRESENTABLE_GAPS,
    TrafficStructureProvider,
    default_structure_provider,
    project_run_to_har,
)


def load_reading_fixture_helpers() -> dict:
    path = ROOT / "tests" / "operations-reading.py"
    source = path.read_text(encoding="utf-8").split("def prove_recorder_body_closure()")[0]
    ns: dict = {"__file__": str(path)}
    exec(compile(source, str(path), "exec"), ns)
    return ns


def test_provider_interface_and_metadata() -> None:
    ns = load_reading_fixture_helpers()
    runs_root = ROOT / ".runs"
    runs_root.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="structure-provider-fixture-", dir=runs_root))
    try:
        ns["fixture"](run)
        provider = default_structure_provider()
        assert isinstance(provider, TrafficStructureProvider)

        first = provider.derive(run)
        second = provider.derive(run)
        assert first.generation == second.generation
        assert first.metadata == second.metadata
        assert first.metadata.provider == "uklok-internal"
        assert first.metadata.provider_version
        assert first.metadata.provider_config_hash
        assert first.metadata.input_projection_hash
        assert first.metadata.output_hash
        assert first.index["integrity"]["reconciles"] is True
        provider.verify(run)

        step_reading = provider.derive(run, step="step_a")
        assert step_reading.metadata.provider_config_hash != first.metadata.provider_config_hash
        assert step_reading.metadata.input_projection_hash != first.metadata.input_projection_hash
        assert step_reading.metadata.output_hash != first.metadata.output_hash
        provider.verify(run)
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_sanitized_har_projection_and_provenance_boundary() -> None:
    ns = load_reading_fixture_helpers()
    runs_root = ROOT / ".runs"
    runs_root.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="structure-provider-har-", dir=runs_root))
    try:
        ns["fixture"](run)
        projection = project_run_to_har(run, sanitize=True)
        assert projection.har["log"]["version"] == "1.2"
        entries = projection.har["log"]["entries"]
        assert len(entries) == 7
        assert len(projection.provenance_index) == 7
        assert projection.unrepresentable_gaps == HAR_UNREPRESENTABLE_GAPS

        har_text = json.dumps(projection.har)
        for secret in (
            ns["AUTH_SECRET"],
            ns["COOKIE_SECRET"],
            ns["SERVER_COOKIE_SECRET"],
            ns["RESPONSE_SECRET"],
            ns["GQL_VARIABLE_SECRET"],
            ns["GQL_LITERAL_SECRET"],
            ns["SIGNED_SECRET"],
        ):
            assert secret not in har_text, f"secret leaked into HAR projection: {secret}"

        urls = [entry["request"]["url"] for entry in entries]
        assert all("/home" not in url and "logo.png" not in url and "app.js" not in url for url in urls)
        assert any("/users/654321" in url for url in urls)
        assert all("/users/123456" not in url for url in urls)

        r1_prov = next(item for item in projection.provenance_index if item["request_id"] == "r1")
        assert r1_prov["redirects"] == 1
        assert r1_prov["attribution"] == "attributed"
        assert r1_prov["body_evidence"]["status"] == "captured"

        nobody_prov = next(item for item in projection.provenance_index if item["request_id"] == "nobody")
        assert nobody_prov["body_evidence"]["status"] == "unobserved"

        step_a_proj = project_run_to_har(run, step="step_a", sanitize=True)
        assert len(step_a_proj.har["log"]["entries"]) == 1
        assert step_a_proj.provenance_index[0]["request_id"] == "r1"
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_har_projection_preserves_json_property_names_equal_to_secrets() -> None:
    ns = load_reading_fixture_helpers()
    runs_root = ROOT / ".runs"
    runs_root.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="structure-provider-keyname-", dir=runs_root))
    try:
        (run / "steps" / "01-step_a").mkdir(parents=True)
        ns["write_json"](run / "steps" / "01-step_a" / "checkpoint.json", {"step": "step_a"})
        ns["write_jsonl"](
            run / "traffic" / "events.jsonl",
            [
                ns["raw"](
                    1,
                    "Network.requestWillBeSent",
                    "items",
                    {
                        "type": "Fetch",
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.test/items",
                            "headers": {
                                "Authorization": "Bearer Authorization",
                                "Content-Type": "application/json",
                            },
                            "postData": json.dumps({"name": "ordinary"}),
                        },
                    },
                ),
                ns["raw"](
                    2,
                    "Network.responseReceived",
                    "items",
                    {
                        "type": "Fetch",
                        "response": {
                            "url": "https://api.example.test/items",
                            "status": 200,
                            "mimeType": "application/json",
                            "headers": {},
                        },
                    },
                ),
                ns["body"](3, "items", json.dumps({"Authorization": "published-field-value", "ok": True})),
            ],
        )
        ns["write_jsonl"](
            run / "traffic" / "checkpoints.jsonl",
            [{"step": "step_a", "from_seq": 1, "through_seq": 3, "target_id": "page-1"}],
        )

        projection = project_run_to_har(run, sanitize=True)
        entry = projection.har["log"]["entries"][0]
        auth_header = next(h["value"] for h in entry["request"]["headers"] if h["name"] == "Authorization")
        assert "${UKLOK_SECRET_" in auth_header
        body_obj = json.loads(entry["response"]["content"]["text"])
        assert "Authorization" in body_obj
        assert body_obj["Authorization"].startswith("${UKLOK_SECRET_")
        assert "published-field-value" not in json.dumps(body_obj)
    finally:
        shutil.rmtree(run, ignore_errors=True)


test_provider_interface_and_metadata()
test_sanitized_har_projection_and_provenance_boundary()
test_har_projection_preserves_json_property_names_equal_to_secrets()
print("structure provider boundary validation passed")
