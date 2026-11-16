#!/usr/bin/env python3
"""Verify one real reading-honeypot Chrome capture.

The raw recorder observes the shared browser, so other tabs may legitimately be
present in traffic/events.jsonl. This verifier never edits that evidence. It
builds a temporary view containing only the target owned by the honeypot
checkpoints, derives operations there, and checks the reviewed expectations.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "automations" / "_runtime"
AUTOMATION = ROOT / "automations" / "reading_honeypot"
EXPECTATIONS_PATH = AUTOMATION / "expectations.json"
CONTRACT_PATH = AUTOMATION / "contract.toml"
MODULE_PATH = AUTOMATION / "run.py"
sys.path.insert(0, str(RUNTIME))

import operations  # noqa: E402


class VerificationError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must contain a JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise VerificationError(f"cannot read {path}: {exc}") from exc
    values = []
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if isinstance(value, dict):
            values.append(value)
    return values


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def load_automation_module():
    spec = importlib.util.spec_from_file_location("reading_honeypot_fixture", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise VerificationError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_config() -> dict[str, Any]:
    expected = load_json(EXPECTATIONS_PATH)
    if expected.get("schema") != "uklok.browser.reading-honeypot-expectations/v1":
        raise VerificationError("unexpected expectations schema")

    target_steps = expected.get("target_steps")
    if not isinstance(target_steps, list) or not target_steps or not all(isinstance(x, str) for x in target_steps):
        raise VerificationError("target_steps must be a non-empty string array")

    normal = expected.get("normal")
    if not isinstance(normal, dict):
        raise VerificationError("normal expectations are required")
    counts = normal.get("required_operation_counts")
    if not isinstance(counts, dict) or not counts:
        raise VerificationError("normal.required_operation_counts must be a non-empty object")
    if not all(isinstance(key, str) and isinstance(value, int) and value > 0 for key, value in counts.items()):
        raise VerificationError("required operation counts must be positive integers")

    graphql_required = normal.get("graphql_required")
    if not isinstance(graphql_required, list) or not graphql_required:
        raise VerificationError("normal.graphql_required must be a non-empty array")
    identities = []
    for item in graphql_required:
        if not isinstance(item, dict):
            raise VerificationError("each graphql_required item must be an object")
        identity = (item.get("variant"), item.get("operation_name"))
        if not all(isinstance(part, str) and part for part in identity):
            raise VerificationError("graphql_required entries need variant and operation_name")
        identities.append(identity)
    if len(identities) != len(set(identities)):
        raise VerificationError("graphql_required contains duplicate identities")

    fail_cases = expected.get("fail_closed_cases")
    if not isinstance(fail_cases, dict) or set(fail_cases) != {"graphql_comment", "field_name"}:
        raise VerificationError("fail_closed_cases must define graphql_comment and field_name")
    for name, case in fail_cases.items():
        if not isinstance(case, dict) or not isinstance(case.get("error_contains"), str):
            raise VerificationError(f"fail_closed_cases.{name}.error_contains is required")
        markers_for_case = case.get("required_capture_markers")
        if not isinstance(markers_for_case, list) or not markers_for_case:
            raise VerificationError(f"fail_closed_cases.{name}.required_capture_markers is required")

    contract = tomllib.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    inputs = {item.get("name"): item for item in contract.get("inputs", []) if isinstance(item, dict)}
    if set(inputs) != {"trap"}:
        raise VerificationError("reading_honeypot must expose only the trap test-mode input")
    if inputs["trap"].get("type") != "string" or inputs["trap"].get("default") != "none":
        raise VerificationError("trap must be a string defaulting to 'none'")

    module = load_automation_module()
    markers = set(normal.get("forbidden_derived_text") or [])
    graphql_markers = set(fail_cases["graphql_comment"].get("required_capture_markers") or [])
    field_markers = set(fail_cases["field_name"].get("required_capture_markers") or [])
    for name in ("TEST_SECRET", "FIELD_SECRET", "OPAQUE_TOKEN"):
        value = getattr(module, name, None)
        if not isinstance(value, str) or not value:
            raise VerificationError(f"run.py must define non-empty {name}")
    if module.TEST_SECRET not in markers or module.OPAQUE_TOKEN not in markers:
        raise VerificationError("normal leak expectations must track the synthetic secret and opaque token")
    if module.TEST_SECRET not in graphql_markers:
        raise VerificationError("graphql_comment capture markers must track TEST_SECRET")
    if module.FIELD_SECRET not in field_markers:
        raise VerificationError("field_name capture markers must track FIELD_SECRET")

    return expected


def event_target_id(event: dict[str, Any]) -> str | None:
    target = event.get("target")
    if isinstance(target, dict) and target.get("targetId"):
        return str(target["targetId"])
    capture = event.get("capture")
    if isinstance(capture, dict) and capture.get("target_id"):
        return str(capture["target_id"])
    return None


def target_id_from_checkpoints(boundaries: list[dict[str, Any]], target_steps: list[str]) -> str:
    relevant = [item for item in boundaries if item.get("step") in target_steps]
    missing = [item.get("step") for item in relevant if not item.get("target_id")]
    if missing:
        raise VerificationError(f"honeypot checkpoint(s) have no target_id: {sorted(set(missing))}")
    ids = {str(item["target_id"]) for item in relevant if item.get("target_id")}
    if len(ids) != 1:
        raise VerificationError(f"honeypot checkpoints must resolve to exactly one target, observed: {sorted(ids)}")
    if {str(item.get("step")) for item in relevant} != set(target_steps):
        raise VerificationError("capture is missing one or more expected honeypot checkpoint boundaries")
    return next(iter(ids))


def copy_step_checkpoints(source: Path, target: Path) -> None:
    steps = source / "steps"
    if not steps.is_dir():
        raise VerificationError(f"missing step evidence: {steps}")
    copied = 0
    for directory in sorted(steps.iterdir()):
        checkpoint = directory / "checkpoint.json"
        if not checkpoint.is_file():
            continue
        destination = target / "steps" / directory.name
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(checkpoint, destination / "checkpoint.json")
        copied += 1
    if copied == 0:
        raise VerificationError("no checkpoint.json files were available for the target view")


def materialize_target_view(source: Path, expected: dict[str, Any], destination: Path) -> dict[str, Any]:
    events = load_jsonl(source / "traffic" / "events.jsonl")
    boundaries = load_jsonl(source / "traffic" / "checkpoints.jsonl")
    target_steps = list(expected["target_steps"])
    target_id = target_id_from_checkpoints(boundaries, target_steps)

    target_events = [event for event in events if event_target_id(event) == target_id]
    target_boundaries = [item for item in boundaries if str(item.get("target_id") or "") == target_id]
    if not target_events:
        raise VerificationError(f"no traffic events were captured for target {target_id}")

    boundaries_by_step = {
        str(item.get("step")): item
        for item in target_boundaries
        if item.get("step") in target_steps
    }
    for step in target_steps:
        boundary = boundaries_by_step.get(step)
        if boundary is None:
            raise VerificationError(f"missing target traffic boundary for step {step!r}")
        if boundary.get("step_status") != "passed":
            raise VerificationError(
                f"target traffic boundary {step!r} did not pass: {boundary.get('step_status')!r}"
            )
        outcome = (boundary.get("settle") or {}).get("outcome")
        if outcome != "quiet":
            raise VerificationError(
                f"target traffic boundary {step!r} did not settle cleanly: {outcome!r}"
            )

    copy_step_checkpoints(source, destination)
    write_jsonl(destination / "traffic" / "events.jsonl", target_events)
    write_jsonl(destination / "traffic" / "checkpoints.jsonl", target_boundaries)

    return {
        "target_id": target_id,
        "raw_event_count": len(events),
        "target_event_count": len(target_events),
        "raw_boundary_count": len(boundaries),
        "target_boundary_count": len(target_boundaries),
        "settle_outcomes": {
            step: (boundaries_by_step[step].get("settle") or {}).get("outcome")
            for step in target_steps
        },
    }


def derived_text(run: Path) -> str:
    files: list[Path] = []
    if (run / "operations").is_dir():
        files.extend((run / "operations").rglob("*.json"))
    if (run / "steps").is_dir():
        for directory in (run / "steps").glob("*/operations"):
            files.extend(directory.rglob("*.json"))
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(files))


def operation_host(key: str) -> str | None:
    parts = key.split("|")
    if key.startswith("http|") and len(parts) >= 4:
        return parts[2]
    if key.startswith("graphql|") and len(parts) >= 5:
        return parts[1]
    return None


def load_step_records(run: Path, relative: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted((run / "steps").glob(f"*/operations/{relative}")):
        value = load_json(path)
        items = value.get("operations")
        if isinstance(items, list):
            records.extend(item for item in items if isinstance(item, dict))
    return records


def assert_normal(run: Path, index: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    normal = expected["normal"]
    if index.get("integrity", {}).get("reconciles") is not True:
        raise VerificationError("operation reading did not reconcile")
    if index.get("unattributed_count") != 0:
        raise VerificationError(f"expected no unattributed honeypot calls, got {index.get('unattributed_count')}")

    counts = index.get("operation_counts") or {}
    for key, wanted in normal["required_operation_counts"].items():
        actual = counts.get(key)
        if actual != wanted:
            raise VerificationError(f"{key}: expected count {wanted}, got {actual}")

    required_http = set(normal["required_operation_counts"])
    for key in index.get("operation_keys") or []:
        host = operation_host(str(key))
        if not host or not host.endswith(expected["allowed_host_suffix"]):
            raise VerificationError(f"unexpected operation host in target-isolated reading: {key}")
        if str(key).startswith("http|") and key not in required_http:
            method = str(key).split("|", 3)[1]
            if method != "OPTIONS":
                raise VerificationError(f"unexpected non-preflight HTTP operation: {key}")

    endpoints = load_step_records(run, "endpoints.json")
    by_key = {item.get("key"): item for item in endpoints if isinstance(item.get("key"), str)}
    redirect_spec = normal["redirect"]
    redirect = by_key.get(redirect_spec["key"])
    if redirect is None:
        raise VerificationError("redirect operation is missing from endpoint evidence")
    if redirect.get("credential_dependencies") != redirect_spec["credential_dependencies"]:
        raise VerificationError("final redirect hop inherited credential dependencies")
    if redirect.get("response", {}).get("sets_cookies") != redirect_spec["sets_cookies"]:
        raise VerificationError("redirect response cookie evidence does not match expectation")
    provenance = redirect.get("provenance") or []
    if len(provenance) != 1 or provenance[0].get("redirects") != redirect_spec["redirects"]:
        raise VerificationError("redirect provenance did not preserve one redirect hop")
    if provenance[0].get("attribution") != "attributed":
        raise VerificationError("redirect call lost checkpoint attribution")

    graphql = load_step_records(run, "graphql/operations.json")
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for record in graphql:
        variants = record.get("variants") or []
        if len(variants) == 1 and isinstance(record.get("operation_name"), str):
            by_identity[(str(variants[0]), record["operation_name"])] = record

    for requirement in normal["graphql_required"]:
        identity = (requirement["variant"], requirement["operation_name"])
        record = by_identity.get(identity)
        if record is None:
            raise VerificationError(f"missing GraphQL operation {identity}")
        if record.get("parse_status") != requirement["parse_status"]:
            raise VerificationError(f"{identity}: expected parse status {requirement['parse_status']!r}")

    hash_spec = normal["graphql_hash_only"]
    hash_record = next(
        (
            record
            for record in graphql
            if hash_spec["variant"] in (record.get("variants") or [])
            and hash_spec["persisted_hash"] in (record.get("persisted_hashes") or [])
        ),
        None,
    )
    if hash_record is None:
        raise VerificationError("hash-only persisted GraphQL evidence is missing")
    if hash_record.get("parse_status") != hash_spec["parse_status"]:
        raise VerificationError("hash-only persisted query must remain unparsed")
    if hash_spec["reason"] not in (hash_record.get("unparsed_reasons") or []):
        raise VerificationError("hash-only persisted query lost its unparsed reason")

    for operation_name, wanted_properties in normal["batch_result_properties"].items():
        record = by_identity.get(("json-batch", operation_name))
        if record is None:
            raise VerificationError(f"missing GraphQL batch operation {operation_name}")
        properties = set((record.get("observed_result_schema") or {}).get("properties") or {})
        if properties != set(wanted_properties):
            raise VerificationError(
                f"GraphQL batch {operation_name}: expected result properties {wanted_properties}, got {sorted(properties)}"
            )

    text = derived_text(run)
    for marker in normal["forbidden_derived_text"]:
        if marker in text:
            raise VerificationError(f"forbidden fixture marker survived in derived JSON: {marker!r}")

    operations.verify_reading(run)
    return {
        "derive": "published",
        "assembled_api_calls": index["integrity"]["assembled_api_calls"],
        "logical_operation_count": index["integrity"]["logical_operation_count"],
        "operation_key_count": len(index.get("operation_keys") or []),
        "reconciles": True,
    }


def assert_fail_closed(run: Path, expected: dict[str, Any], trap: str) -> dict[str, Any]:
    fail_spec = expected["fail_closed_cases"].get(trap)
    if not isinstance(fail_spec, dict):
        raise VerificationError(f"unknown fail-closed trap: {trap!r}")
    capture_text = (run / "traffic" / "events.jsonl").read_text(encoding="utf-8")
    for marker in fail_spec["required_capture_markers"]:
        if marker not in capture_text:
            raise VerificationError(f"fail-closed probe was not actually captured: missing {marker!r}")

    try:
        operations.derive_operations(run)
    except operations.OperationReadError as exc:
        error = str(exc)
        if fail_spec["error_contains"] not in error:
            raise VerificationError(f"derivation failed for the wrong reason: {error}") from exc
    else:
        raise VerificationError("deliberate secret-publication traps did not fail closed")

    if (run / "operations").exists():
        raise VerificationError("failed derivation published an operations/ index")
    if any((run / "steps").glob("*/operations")):
        raise VerificationError("failed derivation published step operation artifacts")
    if (run / "traffic" / "secrets.env").exists():
        raise VerificationError("failed derivation published traffic/secrets.env")

    return {
        "derive": "failed-closed",
        "trap": trap,
        "error_contains": fail_spec["error_contains"],
        "published": False,
    }


def verify_run(run: Path, expected: dict[str, Any]) -> dict[str, Any]:
    run = run.resolve()
    manifest = load_json(run / "run.json")
    if manifest.get("automation") != "reading_honeypot":
        raise VerificationError(f"not a reading_honeypot run: {manifest.get('automation')!r}")
    if manifest.get("status") != "succeeded":
        raise VerificationError(f"automation run did not succeed: {manifest.get('status')!r}")
    if manifest.get("capture_traffic") is not True:
        raise VerificationError("run was not recorded with --capture-traffic")
    if manifest.get("traffic_observability", {}).get("status") != "complete":
        raise VerificationError(
            f"traffic capture is not complete: {manifest.get('traffic_observability')!r}"
        )

    inputs = manifest.get("inputs") or {}
    trap = inputs.get("trap")
    if trap not in {"none", "graphql_comment", "field_name"}:
        raise VerificationError(f"run.json records an unsupported trap: {trap!r}")

    with tempfile.TemporaryDirectory(prefix="reading-honeypot-verify-") as raw_tmp:
        target_run = Path(raw_tmp)
        isolation = materialize_target_view(run, expected, target_run)
        result = (
            assert_normal(target_run, operations.derive_operations(target_run), expected)
            if trap == "none"
            else assert_fail_closed(target_run, expected, str(trap))
        )

    return {
        "schema": "uklok.browser.reading-honeypot-verification/v1",
        "source_run": str(run),
        "mode": "published" if trap == "none" else "fail-closed",
        "trap": trap,
        "target_isolation": isolation,
        "result": result,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify a real reading-honeypot Chrome capture")
    parser.add_argument("run_dir", nargs="?", type=Path)
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the honeypot expectation/contract wiring without requiring a live run.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        expected = validate_config()
        if args.check_config and args.run_dir is None:
            print("reading honeypot verification config valid")
            return 0
        if args.run_dir is None:
            raise VerificationError("run_dir is required unless --check-config is used")
        report = verify_run(args.run_dir, expected)
    except (VerificationError, operations.OperationReadError, OSError, tomllib.TOMLDecodeError) as exc:
        print(f"FAIL reading honeypot verification: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
