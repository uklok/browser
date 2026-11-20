from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import parse_qsl, urlsplit

import operations

HAR_UNREPRESENTABLE_GAPS: tuple[str, ...] = (
    "checkpoint_and_move_ownership",
    "redirect_hop_count_and_opening_hop_lineage",
    "body_acquisition_state_unobserved_vs_oversized_vs_loading_failed",
    "graphql_batch_entry_indexing",
    "origin_scoped_credential_rules_and_secret_store_lineage",
    "observed_only_non_completeness_and_presence_metadata",
)


@dataclass(frozen=True)
class ProviderMetadata:
    provider: str
    provider_version: str
    provider_config_hash: str
    input_projection_hash: str
    output_hash: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class DerivedStructureReading:
    index: dict[str, Any]
    metadata: ProviderMetadata
    generation: str


@dataclass(frozen=True)
class HarProjectionResult:
    har: dict[str, Any]
    provenance_index: list[dict[str, Any]]
    unrepresentable_gaps: tuple[str, ...]
    input_projection_hash: str


@runtime_checkable
class TrafficStructureProvider(Protocol):
    provider_name: str

    def derive(self, run_dir: Path, *, step: str | None = None) -> DerivedStructureReading:
        ...

    def verify(self, run_dir: Path) -> None:
        ...


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _input_evidence_hash(run_dir: Path, step: str | None) -> str:
    digest = hashlib.sha256()
    for relative in ("traffic/events.jsonl", "traffic/checkpoints.jsonl"):
        path = run_dir / relative
        if not path.is_file():
            raise operations.OperationReadError(f"missing required traffic evidence: {path}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    digest.update((step or "*").encode("utf-8"))
    return digest.hexdigest()[:20]


def _published_output_hash(run_dir: Path) -> str:
    digest = hashlib.sha256()
    roots = [run_dir / "operations"]
    if (run_dir / "steps").is_dir():
        roots.extend(path / "operations" for path in sorted((run_dir / "steps").glob("*")))
    paths: list[Path] = []
    for root in roots:
        if root.is_dir():
            paths.extend(root.rglob("*.json"))
    for path in sorted(paths, key=lambda item: str(item.relative_to(run_dir))):
        digest.update(str(path.relative_to(run_dir)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:20]


def _redact_json_values(value: Any, secrets: operations.Secrets) -> Any:
    """Redact scalar values inside JSON without mutating object property names."""
    if isinstance(value, str):
        return secrets.redact(value)
    if isinstance(value, list):
        return [_redact_json_values(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json_values(child, secrets) for key, child in value.items()}
    return value


def _redact_payload_text(text: str, mime_type: str, secrets: operations.Secrets | None) -> str:
    if secrets is None or not text:
        return text
    if "json" in mime_type.lower():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return secrets.redact(text)
        return json.dumps(_redact_json_values(parsed, secrets), ensure_ascii=False)
    return secrets.redact(text)


def project_run_to_har(
    run_dir: Path,
    *,
    step: str | None = None,
    sanitize: bool = True,
) -> HarProjectionResult:
    """Project UKLOK-assembled API calls into a sanitized HAR 1.2 view.

    HAR is strictly a projection for external tooling interoperability; raw CDP
    events, checkpoint ownership, redirect lineage, and secret storage stay in
    UKLOK-owned files and the accompanying provenance index.
    """
    run = run_dir.resolve()
    assembled, boundaries = operations._assemble(run)
    known_steps = {boundary["step"] for boundary in boundaries}
    if step is not None and step not in known_steps:
        raise operations.OperationReadError(f"unknown captured step: {step}")

    api_calls = [call for call in assembled if operations._api(call)]
    if step is not None:
        api_calls = [call for call in api_calls if call.get("owner") == step]

    secrets, _ = operations._collect(api_calls)
    active_secrets = secrets if sanitize else None

    entries: list[dict[str, Any]] = []
    provenance_index: list[dict[str, Any]] = []

    for index, call in enumerate(api_calls):
        raw_url = str(call.get("url") or "")
        redacted_url = active_secrets.redact(raw_url) if active_secrets else raw_url
        parsed = urlsplit(redacted_url)
        query_items = [
            {"name": name, "value": value}
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]

        req_headers = [
            {
                "name": str(name),
                "value": active_secrets.redact(str(value)) if active_secrets else str(value),
            }
            for name, value in sorted((call.get("request_headers") or {}).items(), key=lambda kv: str(kv[0]).lower())
        ]
        req_ct = operations._header(call.get("request_headers") or {}, "content-type")
        post_data = call.get("post_data")
        request_obj: dict[str, Any] = {
            "method": str(call.get("method") or "GET").upper(),
            "url": redacted_url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": req_headers,
            "queryString": query_items,
            "headersSize": -1,
            "bodySize": len(post_data.encode("utf-8")) if isinstance(post_data, str) else 0,
        }
        if isinstance(post_data, str):
            request_obj["postData"] = {
                "mimeType": req_ct or "application/json",
                "text": _redact_payload_text(post_data, req_ct, active_secrets),
            }

        resp_headers = [
            {
                "name": str(name),
                "value": active_secrets.redact(str(value)) if active_secrets else str(value),
            }
            for name, value in sorted((call.get("response_headers") or {}).items(), key=lambda kv: str(kv[0]).lower())
        ]
        body_text = operations._body_text(call)
        resp_ct = operations._header(call.get("response_headers") or {}, "content-type") or str(call.get("mime") or "")
        content_obj: dict[str, Any] = {
            "size": len(body_text.encode("utf-8")) if body_text is not None else 0,
            "mimeType": resp_ct or "application/octet-stream",
        }
        if body_text is not None:
            content_obj["text"] = _redact_payload_text(body_text, resp_ct, active_secrets)

        status = call.get("status")
        entries.append(
            {
                "startedDateTime": "1970-01-01T00:00:00.000Z",
                "time": 0,
                "request": request_obj,
                "response": {
                    "status": int(status) if status is not None else 0,
                    "statusText": "OK" if status == 200 else "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": resp_headers,
                    "content": content_obj,
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": content_obj["size"],
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
        )

        provenance = operations._provenance(call)
        provenance["har_entry_index"] = index
        provenance["canonical_origin"] = operations._canonical_origin(urlsplit(raw_url))
        provenance["body_evidence"] = operations._body_evidence(call)
        provenance_index.append(provenance)

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "uklok-browser", "version": operations._reader_fingerprint()},
            "entries": entries,
        }
    }
    return HarProjectionResult(
        har=har,
        provenance_index=provenance_index,
        unrepresentable_gaps=HAR_UNREPRESENTABLE_GAPS,
        input_projection_hash=_sha256_json(har),
    )


class InternalOperationsProvider:
    """Default UKLOK-owned structure provider behind the neutral provider interface."""

    provider_name = "uklok-internal"

    def derive(self, run_dir: Path, *, step: str | None = None) -> DerivedStructureReading:
        run = run_dir.resolve()
        index = operations.derive_operations(run, step=step)
        operations.verify_reading(run)
        config_hash = _sha256_json(
            {
                "provider": self.provider_name,
                "step": step,
                "schema": index.get("schema"),
            }
        )
        metadata = ProviderMetadata(
            provider=self.provider_name,
            provider_version=str(index.get("reader_fingerprint") or operations._reader_fingerprint()),
            provider_config_hash=config_hash,
            input_projection_hash=_input_evidence_hash(run, step),
            output_hash=_published_output_hash(run),
        )
        return DerivedStructureReading(
            index=index,
            metadata=metadata,
            generation=str(index["generation"]),
        )

    def verify(self, run_dir: Path) -> None:
        operations.verify_reading(run_dir.resolve())


def default_structure_provider() -> TrafficStructureProvider:
    return InternalOperationsProvider()
