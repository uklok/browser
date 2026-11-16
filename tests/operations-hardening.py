#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "automations" / "_runtime"
sys.path.insert(0, str(RUNTIME))

import operations  # noqa: E402


TARGET = {"targetId": "page-1", "type": "page"}


def raw(seq: int, method: str, request_id: str, params: dict, *, session: str = "session-1") -> dict:
    value = dict(params)
    value["requestId"] = request_id
    return {
        "seq": seq,
        "captured_at": f"2026-11-15T00:00:{seq % 60:02d}+00:00",
        "target": TARGET,
        "cdp": {"sessionId": session, "method": method, "params": value},
    }


def body(seq: int, request_id: str, value: str) -> dict:
    return {
        "seq": seq,
        "captured_at": f"2026-11-15T00:01:{seq % 60:02d}+00:00",
        "target": TARGET,
        "capture": {
            "kind": "response_body",
            "session_id": "session-1",
            "target_id": "page-1",
            "request_id": request_id,
            "status": "captured",
            "body": value,
            "base64_encoded": False,
            "byte_length": len(value.encode()),
        },
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, values) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True) + "\n")


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def make_run(steps: list[str], events, boundaries: list[dict]) -> Path:
    runs = ROOT / ".runs"
    runs.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="operation-hardening-", dir=runs))
    for ordinal, step in enumerate(steps, 1):
        write_json(run / "steps" / f"{ordinal:02d}-{step}" / "checkpoint.json", {"step": step})
    write_jsonl(run / "traffic" / "events.jsonl", events)
    write_jsonl(run / "traffic" / "checkpoints.jsonl", boundaries)
    return run


def snapshot(run: Path) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    roots = [run / "operations"]
    roots.extend(path / "operations" for path in sorted((run / "steps").glob("*")))
    for root in roots:
        if root.is_dir():
            for path in sorted(root.rglob("*.json")):
                values[str(path.relative_to(run))] = path.read_bytes()
    secrets = run / "traffic" / "secrets.env"
    if secrets.is_file():
        values["traffic/secrets.env"] = secrets.read_bytes()
    return values


def test_redirect_replaces_request_facts() -> None:
    secret = "opening-hop-secret"
    run = make_run(
        ["step_a", "step_b"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "redirect",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://a.example/start",
                        "headers": {
                            "Authorization": f"Bearer {secret}",
                            "Content-Type": "application/json",
                        },
                        "postData": json.dumps({"amount": 5, "note": "open"}),
                    },
                },
            ),
            raw(
                2,
                "Network.requestWillBeSent",
                "redirect",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "GET",
                        "url": "https://b.example/final",
                        "headers": {},
                    },
                    "redirectResponse": {"status": 302},
                },
            ),
            raw(
                3,
                "Network.requestWillBeSentExtraInfo",
                "redirect",
                {"headers": {"Authorization": f"Bearer {secret}"}},
            ),
            raw(
                4,
                "Network.responseReceived",
                "redirect",
                {
                    "type": "Fetch",
                    "response": {
                        "url": "https://b.example/final",
                        "status": 200,
                        "mimeType": "application/json",
                        "headers": {},
                    },
                },
            ),
        ],
        [
            {"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"},
            {"step": "step_b", "from_seq": 2, "through_seq": 4, "target_id": "page-1"},
        ],
    )
    try:
        index = operations.derive_operations(run)
        key = "http|GET|b.example|/final"
        assert index["operation_keys"] == [key]
        assert index["steps"]["step_a"]["operation_keys"] == [key]
        assert index["steps"]["step_b"]["operation_keys"] == []
        step = run / "steps" / "01-step_a" / "operations"
        auth = read(step / "auth.json")
        assert auth["dependencies"] == []
        openapi = read(step / "openapi" / operations._host_filename("b.example"))
        final = openapi["paths"]["/final"]["get"]
        assert "requestBody" not in final
        assert final["x-uklok-credential-dependencies"] == []
        assert secret not in (run / "traffic" / "secrets.env").read_text(encoding="utf-8")
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_late_redirect_response_extra_info_does_not_contaminate_final_hop() -> None:
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "redirect-response-extra",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://a.example/start",
                        "headers": {"Content-Type": "application/json"},
                        "postData": json.dumps({"amount": 5}),
                    },
                },
            ),
            raw(
                2,
                "Network.requestWillBeSentExtraInfo",
                "redirect-response-extra",
                {"headers": {}},
            ),
            raw(
                3,
                "Network.requestWillBeSent",
                "redirect-response-extra",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "GET",
                        "url": "https://b.example/final",
                        "headers": {},
                    },
                    "redirectResponse": {"status": 302},
                    "redirectHasExtraInfo": True,
                },
            ),
            raw(
                4,
                "Network.responseReceivedExtraInfo",
                "redirect-response-extra",
                {
                    "statusCode": 302,
                    "headers": {"Set-Cookie": "intermediate=stale-value; Path=/"},
                },
            ),
            raw(
                5,
                "Network.responseReceived",
                "redirect-response-extra",
                {
                    "type": "Fetch",
                    "response": {
                        "url": "https://b.example/final",
                        "status": 200,
                        "mimeType": "application/json",
                        "headers": {},
                    },
                },
            ),
            raw(
                6,
                "Network.responseReceivedExtraInfo",
                "redirect-response-extra",
                {
                    "statusCode": 200,
                    "headers": {"Set-Cookie": "finalcookie=final-value; Path=/"},
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 6, "target_id": "page-1"}],
    )
    try:
        operations.derive_operations(run)
        step = run / "steps" / "01-step_a" / "operations"
        endpoints = read(step / "endpoints.json")["operations"]
        final = next(item for item in endpoints if item["key"] == "http|GET|b.example|/final")
        assert final["response"]["sets_cookies"] == ["finalcookie"]
        derived_json = b"\n".join(
            value
            for key, value in snapshot(run).items()
            if key != "traffic/secrets.env"
        )
        assert b"intermediate" not in derived_json
        assert b"amount" not in derived_json
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_final_response_extra_info_survives_missing_redirect_extra() -> None:
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "redirect-missing-extra",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://a.example/start",
                        "headers": {"Content-Type": "application/json"},
                        "postData": json.dumps({"amount": 5}),
                    },
                },
            ),
            raw(
                2,
                "Network.requestWillBeSent",
                "redirect-missing-extra",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "GET",
                        "url": "https://b.example/final",
                        "headers": {},
                    },
                    "redirectResponse": {"status": 302},
                    "redirectHasExtraInfo": False,
                },
            ),
            raw(
                3,
                "Network.responseReceived",
                "redirect-missing-extra",
                {
                    "type": "Fetch",
                    "hasExtraInfo": True,
                    "response": {
                        "url": "https://b.example/final",
                        "status": 200,
                        "mimeType": "application/json",
                        "headers": {},
                    },
                },
            ),
            raw(
                4,
                "Network.responseReceivedExtraInfo",
                "redirect-missing-extra",
                {
                    "statusCode": 200,
                    "headers": {"Set-Cookie": "finalcookie=final-value; Path=/"},
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 4, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        assert index["operation_keys"] == ["http|GET|b.example|/final"]
        endpoints = read(
            run / "steps" / "01-step_a" / "operations" / "endpoints.json"
        )["operations"]
        final = endpoints[0]
        assert final["response"]["sets_cookies"] == ["finalcookie"]
        derived_json = b"\n".join(
            value
            for key, value in snapshot(run).items()
            if key != "traffic/secrets.env"
        )
        assert b"amount" not in derived_json
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_final_response_extra_info_survives_missing_redirect_extra_without_flag() -> None:
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "redirect-missing-extra-fallback",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://a.example/start",
                        "headers": {},
                    },
                },
            ),
            raw(
                2,
                "Network.requestWillBeSent",
                "redirect-missing-extra-fallback",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "GET",
                        "url": "https://b.example/final",
                        "headers": {},
                    },
                    "redirectResponse": {"status": 302},
                },
            ),
            raw(
                3,
                "Network.responseReceived",
                "redirect-missing-extra-fallback",
                {
                    "type": "Fetch",
                    "response": {
                        "url": "https://b.example/final",
                        "status": 200,
                        "mimeType": "application/json",
                        "headers": {},
                    },
                },
            ),
            raw(
                4,
                "Network.responseReceivedExtraInfo",
                "redirect-missing-extra-fallback",
                {
                    "statusCode": 200,
                    "headers": {"Set-Cookie": "finalcookie=final-value; Path=/"},
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 4, "target_id": "page-1"}],
    )
    try:
        operations.derive_operations(run)
        endpoints = read(
            run / "steps" / "01-step_a" / "operations" / "endpoints.json"
        )["operations"]
        assert endpoints[0]["response"]["sets_cookies"] == ["finalcookie"]
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_ambiguous_same_status_response_extra_fails_closed() -> None:
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "redirect-same-status",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "GET",
                        "url": "https://a.example/start",
                        "headers": {},
                    },
                },
            ),
            raw(
                2,
                "Network.requestWillBeSent",
                "redirect-same-status",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "GET",
                        "url": "https://b.example/final",
                        "headers": {},
                    },
                    "redirectResponse": {"status": 302},
                },
            ),
            raw(
                3,
                "Network.responseReceived",
                "redirect-same-status",
                {
                    "type": "Fetch",
                    "response": {
                        "url": "https://b.example/final",
                        "status": 302,
                        "mimeType": "text/plain",
                        "headers": {},
                    },
                },
            ),
            raw(
                4,
                "Network.responseReceivedExtraInfo",
                "redirect-same-status",
                {
                    "statusCode": 302,
                    "headers": {"Set-Cookie": "ambiguous=do-not-publish; Path=/"},
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 4, "target_id": "page-1"}],
    )
    try:
        operations.derive_operations(run)
        endpoints = read(
            run / "steps" / "01-step_a" / "operations" / "endpoints.json"
        )["operations"]
        assert endpoints[0]["response"]["sets_cookies"] == []
        derived_json = b"\n".join(
            value
            for key, value in snapshot(run).items()
            if key != "traffic/secrets.env"
        )
        assert b"ambiguous" not in derived_json
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_failed_stage_never_publishes() -> None:
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "r1",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/old", "headers": {}}},
            )
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"}],
    )
    try:
        operations.derive_operations(run)
        before = snapshot(run)
        write_jsonl(
            run / "traffic" / "events.jsonl",
            [
                raw(
                    1,
                    "Network.requestWillBeSent",
                    "r1",
                    {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/new", "headers": {}}},
                )
            ],
        )

        real_verify = operations.verify_reading

        def fail_staged_generation(path: Path) -> None:
            real_verify(path)
            if path.name.startswith(".operations-stage-"):
                raise operations.OperationReadError("forced integrity failure in staged generation")

        operations.verify_reading = fail_staged_generation
        try:
            try:
                operations.derive_operations(run)
            except operations.OperationReadError as exc:
                assert "forced integrity failure in staged generation" in str(exc)
            else:
                raise AssertionError("failed staged generation must never publish")
        finally:
            operations.verify_reading = real_verify

        assert snapshot(run) == before
        assert not list(run.glob(".operations-stage-*"))
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_failed_publication_restores_previous_generation() -> None:
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "r1",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/old", "headers": {}}},
            )
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"}],
    )
    try:
        operations.derive_operations(run)
        before = snapshot(run)
        events = [
            raw(
                1,
                "Network.requestWillBeSent",
                "r1",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/new", "headers": {}}},
            )
        ]
        write_jsonl(run / "traffic" / "events.jsonl", events)

        real_verify = operations.verify_reading

        def fail_after_publication_write(path: Path) -> None:
            real_verify(path)
            if path.resolve() == run.resolve():
                raise operations.OperationReadError("forced integrity failure after publication writes")

        operations.verify_reading = fail_after_publication_write
        try:
            try:
                operations.derive_operations(run)
            except operations.OperationReadError as exc:
                assert "forced integrity failure after publication writes" in str(exc)
            else:
                raise AssertionError("forced post-publication verification failure must roll back")
        finally:
            operations.verify_reading = real_verify

        assert snapshot(run) == before
        assert not list(run.glob(".operations-stage-*"))
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_ambiguous_checkpoint_is_unattributed() -> None:
    run = make_run(
        ["step_a", "step_b"],
        [
            raw(
                7,
                "Network.requestWillBeSent",
                "r1",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/ambiguous", "headers": {}}},
            )
        ],
        [
            {"step": "step_a", "from_seq": 1, "through_seq": 10, "target_id": "page-1"},
            {"step": "step_b", "from_seq": 5, "through_seq": 15, "target_id": "page-1"},
        ],
    )
    try:
        index = operations.derive_operations(run)
        assert index["attributed_count"] == 0
        assert index["unattributed_count"] == 1
        item = index["unattributed"][0]
        assert item["attribution"] == "ambiguous"
        assert item["owner_candidates"] == ["step_a", "step_b"]
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_duplicate_checkpoint_is_unattributed() -> None:
    run = make_run(
        ["step_a", "step_b"],
        [
            raw(
                4,
                "Network.requestWillBeSent",
                "r1",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/duplicate", "headers": {}}},
            )
        ],
        [
            {"step": "step_a", "from_seq": 1, "through_seq": 10, "target_id": "page-1"},
            {"step": "step_b", "from_seq": 1, "through_seq": 10, "target_id": "page-1"},
        ],
    )
    try:
        index = operations.derive_operations(run)
        assert index["attributed_count"] == 0
        assert index["unattributed_count"] == 1
        assert index["unattributed"][0]["attribution"] == "ambiguous"
        assert index["unattributed"][0]["owner_candidates"] == ["step_a", "step_b"]
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_checkpoint_corruption_never_manufactures_owner() -> None:
    fixtures = []

    fixtures.append(
        (
            raw(
                3,
                "Network.requestWillBeSent",
                "null-target-overlap",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/null-target-overlap", "headers": {}}},
            ),
            ["step_a", "step_b"],
            [
                {"step": "step_a", "from_seq": 1, "through_seq": 5},
                {"step": "step_b", "from_seq": 1, "through_seq": 5, "target_id": "page-1"},
            ],
            "ambiguous",
            ["step_a", "step_b"],
        )
    )
    fixtures.append(
        (
            raw(
                5,
                "Network.requestWillBeSent",
                "reversed",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/reversed", "headers": {}}},
            ),
            ["step_a"],
            [{"step": "step_a", "from_seq": 10, "through_seq": 1, "target_id": "page-1"}],
            "unattributed",
            [],
        )
    )
    fixtures.append(
        (
            raw(
                8,
                "Network.requestWillBeSent",
                "gap",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/gap", "headers": {}}},
            ),
            ["step_a", "step_b"],
            [
                {"step": "step_a", "from_seq": 1, "through_seq": 5, "target_id": "page-1"},
                {"step": "step_b", "from_seq": 10, "through_seq": 15, "target_id": "page-1"},
            ],
            "unattributed",
            [],
        )
    )
    fixtures.append(
        (
            raw(
                3,
                "Network.requestWillBeSent",
                "target-mismatch",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/target-mismatch", "headers": {}}},
            ),
            ["step_a"],
            [{"step": "step_a", "from_seq": 1, "through_seq": 5, "target_id": "page-other"}],
            "unattributed",
            [],
        )
    )
    missing_target = raw(
        3,
        "Network.requestWillBeSent",
        "missing-opening-target",
        {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/missing-opening-target", "headers": {}}},
    )
    missing_target["target"] = {"type": "page"}
    fixtures.append(
        (
            missing_target,
            ["step_a"],
            [{"step": "step_a", "from_seq": 1, "through_seq": 5, "target_id": "page-1"}],
            "unattributed",
            [],
        )
    )

    for event, steps, boundaries, expected_status, expected_candidates in fixtures:
        run = make_run(steps, [event], boundaries)
        try:
            index = operations.derive_operations(run)
            assert index["attributed_count"] == 0
            assert index["unattributed_count"] == 1
            provenance = index["unattributed"][0]
            assert provenance["attribution"] == expected_status
            assert provenance["owner_candidates"] == expected_candidates
        finally:
            shutil.rmtree(run, ignore_errors=True)


def test_step_regeneration_invalidates_siblings() -> None:
    run = make_run(
        ["step_a", "step_b"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "a",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/users/123456", "headers": {}}},
            ),
            raw(
                2,
                "Network.requestWillBeSent",
                "b",
                {"type": "XHR", "request": {"method": "GET", "url": "https://api.example/widgets/987654", "headers": {}}},
            ),
        ],
        [
            {"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"},
            {"step": "step_b", "from_seq": 2, "through_seq": 2, "target_id": "page-1"},
        ],
    )
    try:
        first = operations.derive_operations(run)
        old_generation = first["generation"]
        step_b_dir = run / "steps" / "02-step_b" / "operations"
        assert read(step_b_dir / "endpoints.json")["generation"] == old_generation

        real_reader_fingerprint = operations._reader_fingerprint
        operations._reader_fingerprint = lambda: "reader-version-b"
        try:
            second = operations.derive_operations(run, step="step_a")
        finally:
            operations._reader_fingerprint = real_reader_fingerprint
        assert second["generation"] != old_generation
        assert second["reader_fingerprint"] == "reader-version-b"
        assert second["scope"]["selected_steps"] == ["step_a"]
        assert second["steps"]["step_a"]["artifact_status"] == "published"
        assert second["steps"]["step_b"]["artifact_status"] == "invalidated"
        assert second["steps"]["step_b"]["generation"] is None
        assert read(run / "steps" / "01-step_a" / "operations" / "endpoints.json")["generation"] == second["generation"]
        assert operations._secret_generation(run) == second["generation"]
        assert not step_b_dir.exists()
        operations.verify_reading(run)
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_graphql_variants_are_explicit() -> None:
    query = quote("query GetThing { thing { id } }")
    batch = [
        {"query": "query BatchA { a { id } }"},
        {"query": "query BatchB { b { id } }"},
    ]
    events = [
        raw(
            1,
            "Network.requestWillBeSent",
            "get",
            {"type": "Fetch", "request": {"method": "GET", "url": f"https://gql.example/graphql?query={query}", "headers": {}}},
        ),
        raw(
            2,
            "Network.requestWillBeSent",
            "raw",
            {
                "type": "Fetch",
                "request": {
                    "method": "POST",
                    "url": "https://gql.example/graphql",
                    "headers": {"Content-Type": "application/graphql"},
                    "postData": "query GetThing { thing { id } }",
                },
            },
        ),
        raw(
            3,
            "Network.requestWillBeSent",
            "batch",
            {
                "type": "Fetch",
                "request": {
                    "method": "POST",
                    "url": "https://gql.example/graphql",
                    "headers": {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer batch-shared-secret",
                    },
                    "postData": json.dumps(batch),
                },
            },
        ),
        raw(
            4,
            "Network.requestWillBeSent",
            "persisted-name",
            {
                "type": "Fetch",
                "request": {
                    "method": "POST",
                    "url": "https://gql.example/graphql",
                    "headers": {"Content-Type": "application/json"},
                    "postData": json.dumps(
                        {
                            "operationName": "PersistedThing",
                            "extensions": {"persistedQuery": {"version": 1, "sha256Hash": "a" * 64}},
                        }
                    ),
                },
            },
        ),
        raw(
            5,
            "Network.requestWillBeSent",
            "persisted-hash",
            {
                "type": "Fetch",
                "request": {
                    "method": "POST",
                    "url": "https://gql.example/graphql",
                    "headers": {"Content-Type": "application/json"},
                    "postData": json.dumps(
                        {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "b" * 64}}}
                    ),
                },
            },
        ),
        raw(
            6,
            "Network.requestWillBeSent",
            "opaque",
            {
                "type": "Fetch",
                "request": {
                    "method": "POST",
                    "url": "https://gql.example/graphql",
                    "headers": {"Content-Type": "application/graphql"},
                    "postData": "opaque graphql payload",
                },
            },
        ),
        body(
            7,
            "batch",
            json.dumps(
                [
                    {"data": {"a": {"id": "a-1"}}},
                    {"errors": [{"message": "batch-b-failed"}]},
                ]
            ),
        ),
    ]
    run = make_run(
        ["step_a"],
        events,
        [{"step": "step_a", "from_seq": 1, "through_seq": 7, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        assert index["total_observed_calls"] == 6
        assert index["logical_operation_observations"] == 7
        assert index["integrity"]["reconciles"] is True
        assert all(key.startswith("graphql|gql.example|/graphql|") for key in index["operation_keys"])

        records = read(run / "steps" / "01-step_a" / "operations" / "graphql" / "operations.json")["operations"]
        by_variant_name = {
            (record["variants"][0], record["operation_name"]): record
            for record in records
        }
        for key in (
            ("get-query", "GetThing"),
            ("raw-application-graphql", "GetThing"),
            ("json-batch", "BatchA"),
            ("json-batch", "BatchB"),
            ("persisted-json", "PersistedThing"),
        ):
            assert by_variant_name[key]["parse_status"] == "parsed"
        batch_a = by_variant_name[("json-batch", "BatchA")]
        batch_b = by_variant_name[("json-batch", "BatchB")]
        assert "data" in batch_a["observed_result_schema"]["properties"]
        assert "errors" not in batch_a["observed_result_schema"]["properties"]
        assert "errors" in batch_b["observed_result_schema"]["properties"]
        assert "data" not in batch_b["observed_result_schema"]["properties"]
        assert by_variant_name[("persisted-json", "PersistedThing")]["documents"] == []
        get_key = by_variant_name[("get-query", "GetThing")]["key"]
        raw_key = by_variant_name[("raw-application-graphql", "GetThing")]["key"]
        assert get_key != raw_key
        hash_only = next(record for record in records if record["operation_name"].startswith("persisted-"))
        assert hash_only["parse_status"] == "unparsed"
        assert hash_only["persisted_hashes"] == ["b" * 64]
        assert hash_only["unparsed_reasons"] == ["persisted-query-document-and-operation-name-missing"]
        unparsed = [record for record in records if record["parse_status"] == "unparsed"]
        assert len(unparsed) == 2
        opaque = next(record for record in unparsed if record["operation_name"].startswith("unparsed-"))
        assert opaque["unparsed_reasons"] == ["graphql-document-not-understood"]
        batch_auth_rules = [
            rule
            for rule in index["credential_rules"]
            if rule["kind"] == "header" and rule["name"] == "Authorization"
        ]
        assert any(
            rule["scope"] == "partial"
            and rule.get("request_keys") == ["session-1:batch"]
            for rule in batch_auth_rules
        )
        assert all(rule["scope"] != "operation" for rule in batch_auth_rules)
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_repeated_graphql_batch_name_keeps_entry_evidence() -> None:
    batch = [
        {
            "operationName": "RepeatedThing",
            "query": "query RepeatedThing($id: ID!) { thing(id: $id) { id } }",
            "variables": {"id": "left"},
        },
        {
            "operationName": "RepeatedThing",
            "query": "query RepeatedThing($id: ID!) { thing(id: $id) { id } }",
            "variables": {"id": "right"},
        },
    ]
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "batch-repeat",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://gql.example/graphql",
                        "headers": {"Content-Type": "application/json"},
                        "postData": json.dumps(batch),
                    },
                },
            ),
            body(
                2,
                "batch-repeat",
                json.dumps(
                    [
                        {"data": {"thing": {"id": "left"}}},
                        {"errors": [{"message": "right-failed"}]},
                    ]
                ),
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 2, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        key = "graphql|gql.example|/graphql|json-batch|RepeatedThing"
        assert index["total_observed_calls"] == 1
        assert index["logical_operation_observations"] == 2
        assert index["operation_counts"][key] == 2

        records = read(
            run / "steps" / "01-step_a" / "operations" / "graphql" / "operations.json"
        )["operations"]
        record = next(item for item in records if item["key"] == key)
        assert record["count"] == 2
        properties = record["observed_result_schema"]["properties"]
        assert "data" in properties
        assert "errors" in properties
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_host_identity_and_openapi_names() -> None:
    urls = [
        "https://API.Example/case",
        "https://api.example:443/case",
        "http://Port.Example:80/default",
        "http://port.example/default",
        "https://weird.example:8443/left",
        "https://weird.example_8443/right",
    ]
    run = make_run(
        ["step_a"],
        (
            raw(
                seq,
                "Network.requestWillBeSent",
                f"r{seq}",
                {"type": "XHR", "request": {"method": "GET", "url": url, "headers": {}}},
            )
            for seq, url in enumerate(urls, 1)
        ),
        [{"step": "step_a", "from_seq": 1, "through_seq": len(urls), "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        keys = index["operation_keys"]
        assert "http|GET|https://api.example|/case" in keys
        assert "http|GET|http://port.example|/default" in keys
        assert all("API.Example" not in key and ":443" not in key and ":80" not in key for key in keys)
        assert index["operation_counts"]["http|GET|https://api.example|/case"] == 2
        assert index["operation_counts"]["http|GET|http://port.example|/default"] == 2

        openapi_dir = run / "steps" / "01-step_a" / "operations" / "openapi"
        files = sorted(openapi_dir.glob("*.json"))
        assert len(files) == 4
        assert len({path.name.lower() for path in files}) == 4
        weird_names = {
            operations._host_filename("https://weird.example:8443"),
            operations._host_filename("https://weird.example_8443"),
        }
        assert len(weird_names) == 2
        assert all((openapi_dir / name).is_file() for name in weird_names)
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_secret_verification_distinguishes_names_from_values() -> None:
    secret = "Authorization"
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "r1",
                {
                    "type": "XHR",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example/safe",
                        "headers": {"Authorization": f"Bearer {secret}"},
                    },
                },
            ),
            raw(
                2,
                "Network.responseReceived",
                "r1",
                {
                    "type": "XHR",
                    "response": {
                        "url": "https://api.example/safe",
                        "status": 200,
                        "mimeType": "application/json",
                        "headers": {},
                    },
                },
            ),
            body(3, "r1", json.dumps({"Authorization": "published-field-value"})),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 3, "target_id": "page-1"}],
    )
    try:
        operations.derive_operations(run)
        operations.verify_reading(run)
        auth = read(run / "steps" / "01-step_a" / "operations" / "auth.json")
        assert any(item["name"] == "Authorization" for item in auth["dependencies"])

        index_path = run / "operations" / "index.json"
        index = read(index_path)
        index["poison"] = secret
        write_json(index_path, index)
        try:
            operations.verify_reading(run)
        except operations.OperationReadError:
            pass
        else:
            raise AssertionError("a true lifted value in derived output must fail closed")
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_lifted_secret_inside_graphql_literal_fails_closed() -> None:
    secret = "header-secret-1234"
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "gql-secret",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://gql.example/graphql",
                        "headers": {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {secret}",
                        },
                        "postData": json.dumps(
                            {
                                "operationName": "Echo",
                                "query": (
                                    'query Echo { echo(note: "prefix-'
                                    + secret
                                    + '-suffix") }'
                                ),
                            }
                        ),
                    },
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"}],
    )
    try:
        try:
            operations.derive_operations(run)
        except operations.OperationReadError as exc:
            assert "secret survived in derived artifact" in str(exc)
        else:
            raise AssertionError("a lifted secret embedded in a GraphQL literal must fail closed")
        assert not (run / "operations").exists()
        assert not (run / "steps" / "01-step_a" / "operations").exists()
        assert not (run / "traffic" / "secrets.env").exists()
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_lifted_secret_inside_graphql_comment_fails_closed() -> None:
    secret = "header-secret-1234"
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "gql-comment-secret",
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://gql.example/graphql",
                        "headers": {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {secret}",
                        },
                        "postData": json.dumps(
                            {
                                "operationName": "Echo",
                                "query": f"query Echo {{ thing {{ id }} }} # note {secret}",
                            }
                        ),
                    },
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"}],
    )
    try:
        try:
            operations.derive_operations(run)
        except operations.OperationReadError as exc:
            assert "secret survived in derived artifact" in str(exc)
        else:
            raise AssertionError("a lifted secret embedded in a GraphQL comment must fail closed")
        assert not (run / "operations").exists()
        assert not (run / "steps" / "01-step_a" / "operations").exists()
        assert not (run / "traffic" / "secrets.env").exists()
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_short_lifted_secret_in_path_fails_closed() -> None:
    secret = "s3cr"
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "r1",
                {
                    "type": "XHR",
                    "request": {
                        "method": "GET",
                        "url": f"https://api.example/reset/{secret}",
                        "headers": {"Authorization": f"Bearer {secret}"},
                    },
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"}],
    )
    try:
        try:
            operations.derive_operations(run)
        except operations.OperationReadError as exc:
            assert "secret survived in derived artifact" in str(exc)
        else:
            raise AssertionError("a short lifted secret in an operation path must fail closed")
        assert not (run / "operations").exists()
        assert not (run / "steps" / "01-step_a" / "operations").exists()
        assert not (run / "traffic" / "secrets.env").exists()
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_lifted_secret_used_as_schema_property_name_fails_closed() -> None:
    secret = "NonsensitiveOpaqueValue"
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "field-secret",
                {
                    "type": "XHR",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example/widgets",
                        "headers": {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {secret}",
                        },
                        "postData": json.dumps({secret: "ordinary-value"}),
                    },
                },
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 1, "target_id": "page-1"}],
    )
    try:
        try:
            operations.derive_operations(run)
        except operations.OperationReadError as exc:
            assert "secret survived in derived artifact" in str(exc)
        else:
            raise AssertionError("a lifted secret used as an observed schema property must fail closed")
        assert not (run / "operations").exists()
        assert not (run / "steps" / "01-step_a" / "operations").exists()
        assert not (run / "traffic" / "secrets.env").exists()
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_opaque_path_material_is_templated() -> None:
    opaque = [
        "A1-b2_C",
        "abc.1234-xy",
        "aB:12-cD",
        "jStkcFiTKsVzcqdhcpWMPdYC",
    ]
    run = make_run(
        ["step_a"],
        [
            raw(
                1,
                "Network.requestWillBeSent",
                "one",
                {"type": "XHR", "request": {"method": "GET", "url": f"https://api.example/challenge/{opaque[0]}", "headers": {}}},
            ),
            raw(
                2,
                "Network.requestWillBeSent",
                "two",
                {"type": "XHR", "request": {"method": "GET", "url": f"https://api.example/session/{opaque[1]}", "headers": {}}},
            ),
            raw(
                3,
                "Network.requestWillBeSent",
                "three",
                {"type": "XHR", "request": {"method": "GET", "url": f"https://api.example/challenge/{opaque[2]}", "headers": {}}},
            ),
            raw(
                4,
                "Network.requestWillBeSent",
                "four",
                {"type": "XHR", "request": {"method": "GET", "url": f"https://api.example/challenge/{opaque[3]}", "headers": {}}},
            ),
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 4, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        assert "http|GET|api.example|/challenge/{id}" in index["operation_keys"]
        assert "http|GET|api.example|/session/{id}" in index["operation_keys"]
        assert index["operation_counts"]["http|GET|api.example|/challenge/{id}"] == 3
        derived = b"\n".join(snapshot(run).values())
        for value in opaque:
            assert value.encode() not in derived
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_stable_alphabetic_paths_are_not_templated() -> None:
    stable = ["acknowledgements", "GetCurrentUserProfile"]
    run = make_run(
        ["step_a"],
        [
            raw(
                seq,
                "Network.requestWillBeSent",
                f"stable-{seq}",
                {
                    "type": "XHR",
                    "request": {
                        "method": "GET",
                        "url": f"https://api.example/{segment}",
                        "headers": {},
                    },
                },
            )
            for seq, segment in enumerate(stable, 1)
        ],
        [{"step": "step_a", "from_seq": 1, "through_seq": 2, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        assert index["operation_keys"] == [
            "http|GET|api.example|/GetCurrentUserProfile",
            "http|GET|api.example|/acknowledgements",
        ]
        assert "http|GET|api.example|/{id}" not in index["operation_keys"]
    finally:
        shutil.rmtree(run, ignore_errors=True)


def equivalent_run(
    *,
    user_id: str,
    secrets: tuple[str, str, str],
    request_ids: tuple[str, str, str],
    request_seqs: tuple[int, int, int],
    reverse: bool,
) -> Path:
    auth_secret, body_secret, gql_secret = secrets
    user_request, widget_request, gql_request = request_ids
    user_seq, widget_seq, gql_seq = request_seqs

    pairs = [
        [
            raw(
                user_seq,
                "Network.requestWillBeSent",
                user_request,
                {
                    "type": "XHR",
                    "request": {
                        "method": "GET",
                        "url": f"https://api.example/users/{user_id}?api_key={auth_secret}",
                        "headers": {"Authorization": f"Bearer {auth_secret}"},
                    },
                },
            ),
            body(user_seq + 1, user_request, json.dumps({"id": int(user_id), "name": "Ada"})),
        ],
        [
            raw(
                widget_seq,
                "Network.requestWillBeSent",
                widget_request,
                {
                    "type": "XHR",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example/widgets",
                        "headers": {"Content-Type": "application/json"},
                        "postData": json.dumps({"token": body_secret, "name": "widget"}),
                    },
                },
            ),
            body(widget_seq + 1, widget_request, json.dumps({"id": "widget-1", "ok": True})),
        ],
        [
            raw(
                gql_seq,
                "Network.requestWillBeSent",
                gql_request,
                {
                    "type": "Fetch",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example/graphql",
                        "headers": {"Content-Type": "application/json"},
                        "postData": json.dumps(
                            {
                                "operationName": "GetThing",
                                "query": "query GetThing($token: String!) { thing(token: $token) { id } }",
                                "variables": {"token": gql_secret},
                            }
                        ),
                    },
                },
            ),
            body(gql_seq + 1, gql_request, json.dumps({"data": {"thing": {"id": "thing-1"}}})),
        ],
    ]
    if reverse:
        pairs.reverse()
    events = [event for pair in pairs for event in pair]
    lower = min(request_seqs)
    upper = max(seq + 1 for seq in request_seqs)
    return make_run(
        ["step_a"],
        events,
        [{"step": "step_a", "from_seq": lower, "through_seq": upper, "target_id": "page-1"}],
    )


def semantic_reading(run: Path) -> dict:
    step = run / "steps" / "01-step_a" / "operations"
    endpoints = read(step / "endpoints.json")["operations"]
    openapi = read(step / "openapi" / operations._host_filename("api.example"))
    gql_model = read(step / "graphql" / "observed-schema.json")["operations"]
    auth = read(step / "auth.json")["dependencies"]
    return {
        "keys": sorted(item["key"] for item in endpoints),
        "paths": {item["key"]: item["path"] for item in endpoints},
        "dependency_names": sorted((item["kind"], item["name"]) for item in auth),
        "user_response_schema": openapi["paths"]["/users/{id}"]["get"]["responses"]["default"]["content"]["application/json"]["schema"],
        "widget_request_schema": openapi["paths"]["/widgets"]["post"]["requestBody"]["content"]["application/json"]["schema"],
        "widget_response_schema": openapi["paths"]["/widgets"]["post"]["responses"]["default"]["content"]["application/json"]["schema"],
        "graphql_models": sorted(
            (
                item["operation_name"],
                json.dumps(item["variables"], sort_keys=True),
                json.dumps(item["result"], sort_keys=True),
            )
            for item in gql_model
        ),
    }


def test_equivalent_runs_keep_semantic_identity() -> None:
    run_a = equivalent_run(
        user_id="123456",
        secrets=("auth-alpha-secret", "body-alpha-secret", "gql-alpha-secret"),
        request_ids=("user-a", "widget-a", "gql-a"),
        request_seqs=(10, 20, 30),
        reverse=False,
    )
    run_b = equivalent_run(
        user_id="987654",
        secrets=("auth-beta-secret", "body-beta-secret", "gql-beta-secret"),
        request_ids=("user-b", "widget-b", "gql-b"),
        request_seqs=(410, 310, 210),
        reverse=True,
    )
    try:
        index_a = operations.derive_operations(run_a)
        index_b = operations.derive_operations(run_b)
        expected_keys = [
            "graphql|api.example|/graphql|json|GetThing",
            "http|GET|api.example|/users/{id}",
            "http|POST|api.example|/widgets",
        ]
        assert index_a["operation_keys"] == index_b["operation_keys"] == expected_keys
        assert semantic_reading(run_a) == semantic_reading(run_b)
        assert semantic_reading(run_a)["dependency_names"] == [
            ("body", "token"),
            ("body", "variables.token"),
            ("header", "Authorization"),
            ("query", "api_key"),
        ]
    finally:
        shutil.rmtree(run_a, ignore_errors=True)
        shutil.rmtree(run_b, ignore_errors=True)


def test_scale_reconciliation() -> None:
    count = int(os.environ.get("UKLOK_OPERATION_SCALE_CALLS", "50000"))
    assert count >= 1000 and count % 4 == 0
    per_step = count // 4
    steps = ["step_a", "step_b", "step_c", "step_d"]
    boundaries = [
        {
            "step": step,
            "from_seq": ordinal * per_step + 1,
            "through_seq": (ordinal + 1) * per_step,
            "target_id": "page-1",
        }
        for ordinal, step in enumerate(steps)
    ]
    body_request_seqs = [ordinal * per_step + 1 for ordinal in range(4)]
    near_limit_body = json.dumps({"blob": "x" * (1024 * 1024 - 1024)})

    def scale_events():
        for seq in range(1, count + 1):
            group = (seq - 1) % 40
            yield raw(
                seq,
                "Network.requestWillBeSent",
                f"r{seq}",
                {
                    "type": "XHR",
                    "request": {
                        "method": "POST",
                        "url": f"https://api.example/resource-{group:02d}/items/{100000 + seq}",
                        "headers": {"Content-Type": "application/json"},
                        "postData": json.dumps({"value": seq % 7}),
                    },
                },
            )
        for offset, request_seq in enumerate(body_request_seqs, 1):
            yield body(count + offset, f"r{request_seq}", near_limit_body)

    run = make_run(steps, scale_events(), boundaries)
    try:
        index = operations.derive_operations(run)
        assert index["total_observed_calls"] == count
        assert index["attributed_count"] == count
        assert index["unattributed_count"] == 0
        assert index["integrity"]["grouped_call_count"] == count
        assert index["integrity"]["reconciles"] is True
        assert len(index["operation_keys"]) == 40
        assert sum(index["operation_counts"].values()) == count

        captured_bodies = 0
        for directory in sorted((run / "steps").glob("*")):
            endpoints = read(directory / "operations" / "endpoints.json")["operations"]
            captured_bodies += sum(
                evidence["status"] == "captured"
                for operation in endpoints
                for evidence in operation["response"]["body_evidence"]
            )
        assert captured_bodies == 4

        first = snapshot(run)
        operations.derive_operations(run)
        second = snapshot(run)
        assert first == second
    finally:
        shutil.rmtree(run, ignore_errors=True)



def test_origin_identity_scopes_operations_openapi_and_credentials() -> None:
    urls = [
        "http://API.Example/items",
        "http://api.example:80/items",
        "https://API.Example/items",
        "https://api.example:443/items",
    ]
    events = [
        raw(seq, "Network.requestWillBeSent", f"origin-{seq}", {
            "type": "XHR",
            "request": {
                "method": "GET", "url": url,
                "headers": {"Authorization": "Bearer http-secret" if url.startswith("http://") else "Bearer https-secret"},
            },
        })
        for seq, url in enumerate(urls, 1)
    ]
    run = make_run(
        ["step_a"], events,
        [{"step": "step_a", "from_seq": 1, "through_seq": 4, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        assert index["operation_counts"] == {
            "http|GET|http://api.example|/items": 2,
            "http|GET|https://api.example|/items": 2,
        }
        assert index["attributed_count"] == 4
        scoped = [r for r in index["credential_rules"] if r["name"] == "Authorization"]
        assert {r["context"] for r in scoped} == {"http://api.example", "https://api.example"}
        assert all(r["scope"] == "domain" and r["observed_calls"] == 2 for r in scoped)
        assert len({tuple(r["placeholders"]) for r in scoped}) == 2

        directory = run / "steps" / "01-step_a" / "operations" / "openapi"
        files = sorted(directory.glob("*.json"))
        assert len(files) == 2
        assert len({p.name.lower() for p in files}) == 2
        for origin in ("http://api.example", "https://api.example"):
            document = read(directory / operations._host_filename(origin))
            assert document["servers"] == [{"url": origin}]
            assert document["paths"]["/items"]["get"]["x-uklok-observed-count"] == 2
        operations.verify_reading(run)
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_ownerless_checkpoint_boundaries_fail_closed() -> None:
    for missing in ({}, {"step": None}, {"step": ""}, {"step": "   "}):
        run = make_run(
            ["step_a"],
            [raw(2, "Network.requestWillBeSent", "ownerless", {
                "type": "XHR", "request": {
                    "method": "GET", "url": "https://api.example/items", "headers": {},
                },
            })],
            [{**missing, "from_seq": 1, "through_seq": 3, "target_id": "page-1"}],
        )
        try:
            index = operations.derive_operations(run)
            assert index["attributed_count"] == 0
            assert index["unattributed_count"] == 1
            assert index["unattributed"][0]["attribution"] == "unattributed"
            assert index["unattributed"][0]["owner_candidates"] == []
            assert "None" not in index["steps"]
        finally:
            shutil.rmtree(run, ignore_errors=True)

    run = make_run(
        ["step_a"],
        [raw(2, "Network.requestWillBeSent", "legacy", {
            "type": "XHR", "request": {
                "method": "GET", "url": "https://api.example/items", "headers": {},
            },
        })],
        [{"step": "step_a", "from_seq": 1, "through_seq": 3, "target_id": "page-1"}],
    )
    try:
        index = operations.derive_operations(run)
        assert index["attributed_count"] == 1
        assert index["unattributed_count"] == 0
        assert "step_a" in index["steps"]
    finally:
        shutil.rmtree(run, ignore_errors=True)


test_origin_identity_scopes_operations_openapi_and_credentials()
test_ownerless_checkpoint_boundaries_fail_closed()
test_redirect_replaces_request_facts()
test_late_redirect_response_extra_info_does_not_contaminate_final_hop()
test_final_response_extra_info_survives_missing_redirect_extra()
test_final_response_extra_info_survives_missing_redirect_extra_without_flag()
test_ambiguous_same_status_response_extra_fails_closed()
test_failed_stage_never_publishes()
test_failed_publication_restores_previous_generation()
test_ambiguous_checkpoint_is_unattributed()
test_duplicate_checkpoint_is_unattributed()
test_checkpoint_corruption_never_manufactures_owner()
test_step_regeneration_invalidates_siblings()
test_graphql_variants_are_explicit()
test_repeated_graphql_batch_name_keeps_entry_evidence()
test_host_identity_and_openapi_names()
test_secret_verification_distinguishes_names_from_values()
test_lifted_secret_inside_graphql_literal_fails_closed()
test_lifted_secret_inside_graphql_comment_fails_closed()
test_short_lifted_secret_in_path_fails_closed()
test_lifted_secret_used_as_schema_property_name_fails_closed()
test_opaque_path_material_is_templated()
test_stable_alphabetic_paths_are_not_templated()
test_equivalent_runs_keep_semantic_identity()
test_scale_reconciliation()

print("operation hardening fixture validation passed")
