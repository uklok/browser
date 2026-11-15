from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

API_TYPES = {"XHR", "Fetch", "EventSource"}
ASSET_TYPES = {"Stylesheet", "Image", "Media", "Font", "Script"}
JSON_MARKERS = ("application/json", "+json", "application/graphql-response+json")
SENSITIVE = re.compile(r"(authorization|authentication|api.?key|access.?key|token|secret|client.?secret|password|passwd|session|cookie|credential|csrf|xsrf|signature|hmac)", re.I)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{27,}$", re.I)
MIXED_ID = re.compile(r"^[A-Za-z0-9_-]{12,}$")
GQL_NAME = re.compile(r"\b(?:query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)")
GQL_IDENTITY_LITERAL = re.compile(r'("(?:\\.|[^"])*"|\b[-+]?\d+(?:\.\d+)?\b)')
GQL_SECRET_ARG = re.compile(r"""([_A-Za-z][_0-9A-Za-z]*(?:token|secret|password|passwd|api_?key|access_?key|client_?secret|session|credential|csrf|xsrf|signature|hmac)[_0-9A-Za-z]*)\s*:\s*("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[-+]?\d+(?:\.\d+)?|true|false|null)""", re.I)


class OperationReadError(RuntimeError):
    pass


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise OperationReadError(f"missing required traffic evidence: {path}")
    out = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OperationReadError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if isinstance(value, dict):
            out.append(value)
    return out


def _key(session: Any, request: Any) -> str:
    return f"{session or 'browser'}:{request or 'unknown'}"


def _headers(value: Any) -> dict[str, Any]:
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


def _merge_headers(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    result = dict(left)
    lower = {k.lower(): k for k in result}
    for key, value in right.items():
        previous = lower.get(key.lower())
        if previous and previous != key:
            result.pop(previous, None)
        result[key] = value
        lower[key.lower()] = key
    return result


def _header(headers: dict[str, Any], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value)
    return ""


def _new_call(key: str, session: Any, request: Any) -> dict[str, Any]:
    return {
        "key": key,
        "session_id": str(session) if session is not None else None,
        "request_id": str(request) if request is not None else None,
        "target_id": None,
        "opening_target_id": None,
        "opening_seq": None,
        "last_seq": None,
        "method": None,
        "url": None,
        "type": None,
        "request_headers": {},
        "request_hop": 0,
        "request_extra_info_hop": 0,
        "pending_request_extra_headers": {},
        "response_headers": {},
        "post_data": None,
        "status": None,
        "mime": None,
        "redirects": 0,
        "body": None,
        "owner": None,
        "owner_status": "unattributed",
        "owner_candidates": [],
    }


def _assemble(run: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    calls: dict[str, dict[str, Any]] = {}

    def ensure(session: Any, request: Any) -> dict[str, Any]:
        key = _key(session, request)
        calls.setdefault(key, _new_call(key, session, request))
        return calls[key]

    for envelope in _jsonl(run / "traffic" / "events.jsonl"):
        try:
            seq = int(envelope.get("seq"))
        except (TypeError, ValueError):
            continue
        target = envelope.get("target") or {}
        target_id = str(target.get("targetId")) if isinstance(target, dict) and target.get("targetId") else None
        raw = envelope.get("cdp")
        if isinstance(raw, dict):
            params = raw.get("params") or {}
            if not isinstance(params, dict):
                params = {}
            request_id = params.get("requestId")
            if request_id is not None:
                call = ensure(raw.get("sessionId"), request_id)
                call["last_seq"] = seq
                call["target_id"] = call["target_id"] or target_id
                method = raw.get("method")
                if method == "Network.requestWillBeSent":
                    request = params.get("request") or {}
                    call["request_hop"] += 1
                    redirect = call["opening_seq"] is not None
                    if not redirect:
                        call["opening_seq"] = seq
                        call["opening_target_id"] = target_id
                    else:
                        call["redirects"] += 1
                    call["method"] = str(request.get("method") or "UNKNOWN")
                    call["url"] = str(request.get("url") or "")
                    call["type"] = str(params.get("type") or "Other")
                    # A redirect keeps request identity + opening ownership, not the
                    # previous hop's request-only facts. ExtraInfo can arrive before
                    # or after requestWillBeSent, so associate it by hop order.
                    pending = call["pending_request_extra_headers"].pop(call["request_hop"], {})
                    call["request_headers"] = _merge_headers(_headers(request.get("headers")), pending)
                    call["post_data"] = request.get("postData") if isinstance(request.get("postData"), str) else None
                    if redirect:
                        call["response_headers"] = {}
                        call["status"] = None
                        call["mime"] = None
                        call["body"] = None
                elif method == "Network.requestWillBeSentExtraInfo":
                    call["request_extra_info_hop"] += 1
                    hop = call["request_extra_info_hop"]
                    headers = _headers(params.get("headers"))
                    if hop == call["request_hop"]:
                        call["request_headers"] = _merge_headers(call["request_headers"], headers)
                    elif hop > call["request_hop"]:
                        previous = call["pending_request_extra_headers"].get(hop, {})
                        call["pending_request_extra_headers"][hop] = _merge_headers(previous, headers)
                elif method == "Network.responseReceived":
                    response = params.get("response") or {}
                    call["url"] = call["url"] or response.get("url")
                    call["type"] = str(params.get("type") or call["type"] or "Other")
                    call["status"] = response.get("status")
                    call["mime"] = str(response.get("mimeType") or call["mime"] or "")
                    call["response_headers"] = _merge_headers(call["response_headers"], _headers(response.get("headers")))
                elif method == "Network.responseReceivedExtraInfo":
                    call["response_headers"] = _merge_headers(call["response_headers"], _headers(params.get("headers")))
                    call["status"] = call["status"] if call["status"] is not None else params.get("statusCode")
                elif method == "Network.loadingFailed" and call["body"] is None:
                    call["body"] = {"status": "unavailable", "reason": "loading_failed"}

        fact = envelope.get("capture")
        if isinstance(fact, dict) and fact.get("kind") == "response_body":
            call = ensure(fact.get("session_id"), fact.get("request_id"))
            call["last_seq"] = seq
            call["target_id"] = call["target_id"] or fact.get("target_id") or target_id
            call["url"] = call["url"] or fact.get("url")
            call["method"] = call["method"] or fact.get("method")
            call["type"] = call["type"] or fact.get("type")
            call["body"] = dict(fact)

    boundaries = []
    for raw in _jsonl(run / "traffic" / "checkpoints.jsonl"):
        try:
            boundaries.append(
                {
                    "step": str(raw.get("step")),
                    "from_seq": int(raw.get("from_seq")),
                    "through_seq": int(raw.get("through_seq")),
                    "target_id": str(raw.get("target_id")) if raw.get("target_id") else None,
                }
            )
        except (TypeError, ValueError):
            continue
    boundaries.sort(key=lambda x: (x["from_seq"], x["through_seq"]))

    for call in calls.values():
        opening = call["opening_seq"]
        if opening is None:
            call["owner_status"] = "opening-missing"
            continue
        matches = []
        for boundary in boundaries:
            if not (boundary["from_seq"] <= opening <= boundary["through_seq"]):
                continue
            if boundary["target_id"] and boundary["target_id"] != call["opening_target_id"]:
                continue
            matches.append(boundary)
        call["owner_candidates"] = [boundary["step"] for boundary in matches]
        if len(matches) == 1:
            call["owner"] = matches[0]["step"]
            call["owner_status"] = "attributed"
        elif len(matches) > 1:
            call["owner_status"] = "ambiguous"
        else:
            call["owner_status"] = "unattributed"
    return list(calls.values()), boundaries


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


def _identifier(segment: str) -> bool:
    decoded = unquote(segment)
    if UUID.fullmatch(decoded) or (decoded.isdigit() and len(decoded) >= 4):
        return True
    if re.fullmatch(r"[0-9a-f]{12,}", decoded, re.I):
        return True
    if MIXED_ID.fullmatch(decoded) and any(c.isalpha() for c in decoded) and any(c.isdigit() for c in decoded):
        return True

    length = len(decoded)
    if length < 7:
        return False
    unique_ratio = len(set(decoded)) / max(length, 1)
    digits = sum(c.isdigit() for c in decoded)
    punctuation = sum(not c.isalnum() for c in decoded)
    has_alpha = any(c.isalpha() for c in decoded)
    mixed_case = any(c.islower() for c in decoded) and any(c.isupper() for c in decoded)

    # Generic opaque material: enough independent character classes/variation to
    # behave like a session/challenge/token segment, without provider grammars.
    if punctuation >= 2 and has_alpha and digits >= 2 and len(set(decoded)) >= 6:
        return True
    if length >= 8 and punctuation and has_alpha and digits and unique_ratio >= 0.70 and (mixed_case or digits >= 3):
        return True
    if length >= 9 and has_alpha and digits and unique_ratio >= 0.75 and (mixed_case or digits >= 3):
        return True
    # Long opaque encodings are often alphabetic (for example base64 without
    # padding/digits). Entropy catches that shape without naming a provider.
    if (
        length >= 16
        and has_alpha
        and not digits
        and not punctuation
        and unique_ratio >= 0.55
        and _entropy(decoded) >= 3.5
    ):
        return True
    return False


def _template(path: str) -> tuple[str, list[str]]:
    parts = path.split("/")
    params, n = [], 0
    for i, part in enumerate(parts):
        if part and _identifier(part):
            n += 1
            name = "id" if n == 1 else f"id{n}"
            parts[i] = "{" + name + "}"
            params.append(name)
    value = "/".join(parts) or "/"
    return (value if value.startswith("/") else "/" + value), params


def _parse_json(value: Any) -> Any:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _body_text(call: dict[str, Any]) -> str | None:
    fact = call.get("body") or {}
    if fact.get("status") != "captured" or not isinstance(fact.get("body"), str):
        return None
    if fact.get("base64_encoded"):
        try:
            return base64.b64decode(fact["body"]).decode("utf-8")
        except Exception:
            return None
    return fact["body"]


def _persisted_hash(payload: dict[str, Any]) -> str | None:
    extensions = payload.get("extensions")
    if not isinstance(extensions, dict):
        return None
    persisted = extensions.get("persistedQuery")
    if not isinstance(persisted, dict):
        return None
    for key in ("sha256Hash", "hash"):
        value = persisted.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _gql_descriptor(payload: Any, variant: str, entry_index: int | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:12]
        return {
            "parsed": False,
            "variant": variant,
            "name": None,
            "identity_name": "unparsed-" + fingerprint,
            "query": None,
            "payload": None,
            "persisted_hash": None,
            "reason": "graphql-entry-is-not-an-object",
            "entry_index": entry_index,
        }

    query = payload.get("query")
    explicit_name = payload.get("operationName")
    name = explicit_name.strip() if isinstance(explicit_name, str) and explicit_name.strip() else None
    persisted_hash = _persisted_hash(payload)
    reason = None
    parsed = False

    if isinstance(query, str) and query.strip():
        if name is None:
            match = GQL_NAME.search(query)
            if match:
                name = match.group(1)
            elif "{" in query:
                structural = GQL_IDENTITY_LITERAL.sub("<value>", query)
                normalized = " ".join(structural.split())
                name = "anonymous-" + hashlib.sha256(normalized.encode()).hexdigest()[:12]
        parsed = name is not None
        if not parsed:
            reason = "graphql-document-not-understood"
    elif persisted_hash:
        if name is not None:
            parsed = True
        else:
            name = "persisted-" + hashlib.sha256(persisted_hash.encode()).hexdigest()[:12]
            reason = "persisted-query-document-and-operation-name-missing"
    else:
        reason = "graphql-document-or-persisted-hash-missing"

    fingerprint_source = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:12]
    return {
        "parsed": parsed,
        "variant": variant,
        "name": name,
        "identity_name": name or "unparsed-" + fingerprint,
        "query": query if isinstance(query, str) else None,
        "payload": payload,
        "persisted_hash": persisted_hash,
        "reason": reason,
        "entry_index": entry_index,
    }


def _looks_graphql_payload(value: Any) -> bool:
    return isinstance(value, dict) and (
        "query" in value
        or "operationName" in value
        or _persisted_hash(value) is not None
    )


def _gql_entries(call: dict[str, Any]) -> list[dict[str, Any]]:
    method = str(call.get("method") or "").upper()
    url = urlsplit(str(call.get("url") or ""))
    request_ct = _header(call.get("request_headers") or {}, "content-type").lower()

    if method == "GET":
        params = dict(parse_qsl(url.query, keep_blank_values=True))
        if "query" in params or "operationName" in params or "extensions" in params:
            payload: dict[str, Any] = {}
            if "query" in params:
                payload["query"] = params["query"]
            if "operationName" in params:
                payload["operationName"] = params["operationName"]
            for key in ("variables", "extensions"):
                if key in params:
                    parsed = _parse_json(params[key])
                    payload[key] = parsed if parsed is not None else params[key]
            return [_gql_descriptor(payload, "get-query")]

    if "application/graphql" in request_ct:
        text = call.get("post_data")
        payload = {"query": text} if isinstance(text, str) else {}
        return [_gql_descriptor(payload, "raw-application-graphql")]

    payload = _parse_json(call.get("post_data"))
    if isinstance(payload, list) and any(_looks_graphql_payload(item) for item in payload):
        return [_gql_descriptor(item, "json-batch", index) for index, item in enumerate(payload)]
    if _looks_graphql_payload(payload):
        variant = "persisted-json" if isinstance(payload, dict) and not isinstance(payload.get("query"), str) and _persisted_hash(payload) else "json"
        return [_gql_descriptor(payload, variant)]
    return []


def _gql(call: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    entries = _gql_entries(call)
    if not entries:
        return None, None
    first = entries[0]
    if not first["parsed"]:
        return None, first.get("payload")
    return str(first["identity_name"]), first.get("payload")


def _api(call: dict[str, Any]) -> bool:
    resource = call.get("type") or "Other"
    request_ct = _header(call["request_headers"], "content-type").lower()
    response_ct = (_header(call["response_headers"], "content-type") + ";" + str(call.get("mime") or "")).lower()
    if resource in ASSET_TYPES:
        return False
    if resource == "Document" and "text/html" in response_ct:
        return False
    if _gql_entries(call):
        return True
    return (
        resource in API_TYPES
        or any(marker in request_ct or marker in response_ct for marker in JSON_MARKERS)
        or "text/event-stream" in response_ct
    )


def _canonical_host(url: Any) -> str:
    hostname = (url.hostname or "").lower()
    if not hostname:
        return "unknown-host"
    scheme = (url.scheme or "https").lower()
    try:
        port = url.port
    except ValueError:
        port = None
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    rendered = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    return f"{rendered}:{port}" if port is not None else rendered


def _identities(call: dict[str, Any]) -> list[dict[str, Any]]:
    url = urlsplit(str(call.get("url") or ""))
    path, path_params = _template(url.path or "/")
    method = str(call.get("method") or "UNKNOWN").upper()
    scheme = (url.scheme or "https").lower()
    host = _canonical_host(url)
    gql_entries = _gql_entries(call)
    if gql_entries:
        return [
            {
                "key": f"graphql|{host}|{path}|{entry['variant']}|{entry['identity_name']}",
                "kind": "graphql",
                "host": host,
                "scheme": scheme,
                "path": path,
                "path_params": path_params,
                "method": method,
                "gql_name": entry["identity_name"],
                "payload": entry.get("payload"),
                "gql": entry,
            }
            for entry in gql_entries
        ]
    return [
        {
            "key": f"http|{method}|{host}|{path}",
            "kind": "http",
            "host": host,
            "scheme": scheme,
            "path": path,
            "path_params": path_params,
            "method": method,
        }
    ]


def _identity(call: dict[str, Any]) -> dict[str, Any]:
    return _identities(call)[0]


def _identity_for_key(call: dict[str, Any], key: str) -> dict[str, Any]:
    return next(identity for identity in _identities(call) if identity["key"] == key)


class Secrets:
    def __init__(self) -> None:
        self.values: list[str] = []
        self.refs: dict[str, str] = {}

    def add(self, value: Any) -> str | None:
        if value is None or isinstance(value, (dict, list)):
            return None
        text = str(value)
        if not text:
            return None
        if text not in self.refs:
            self.values.append(text)
            self.refs[text] = "$" + f"{{UKLOK_SECRET_{len(self.values):03d}}}"
        return self.refs[text]

    def redact(self, text: str) -> str:
        for secret in sorted(self.values, key=len, reverse=True):
            text = text.replace(secret, self.refs[secret])
        return text

    def redact_graphql(self, text: str) -> str:
        def replace(match: re.Match[str]) -> str:
            raw = match.group(0)
            if raw.startswith('"'):
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError:
                    value = raw[1:-1]
            else:
                value = raw
            ref = self.refs.get(str(value))
            return json.dumps(ref) if ref is not None else raw

        return GQL_IDENTITY_LITERAL.sub(replace, text)


def _sensitive(name: str) -> bool:
    camel_spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    tokens = {part for part in re.split(r"[^a-z0-9]+", camel_spaced.lower()) if part}
    return bool({"auth", "sig"} & tokens) or bool(SENSITIVE.search(name))


def _cookies(value: str) -> list[tuple[str, str]]:
    out = []
    for part in value.split(";"):
        if "=" in part:
            name, val = part.split("=", 1)
            if name.strip():
                out.append((name.strip(), val.strip()))
    return out


def _set_cookies(value: str) -> list[tuple[str, str]]:
    out = []
    for line in value.splitlines() or [value]:
        first = line.split(";", 1)[0]
        if "=" in first:
            name, val = first.split("=", 1)
            if name.strip():
                out.append((name.strip(), val.strip()))
    return out


def _walk_sensitive(value: Any, secrets: Secrets, deps: list[dict[str, str]], prefix: str = "", response: bool = False) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if _sensitive(str(key)) and not isinstance(child, (dict, list)):
                ref = secrets.add(child)
                if ref and not response:
                    deps.append({"kind": "body", "name": path, "placeholder": ref})
            _walk_sensitive(child, secrets, deps, path, response)
    elif isinstance(value, list):
        for child in value:
            _walk_sensitive(child, secrets, deps, prefix, response)


def _collect(calls: list[dict[str, Any]]) -> tuple[Secrets, dict[str, list[dict[str, str]]]]:
    secrets, by_call = Secrets(), {}
    for call in calls:
        deps = []
        for name, value in call["request_headers"].items():
            lower, text = name.lower(), str(value)
            if lower == "authorization":
                parts = text.split(None, 1)
                ref = secrets.add(parts[1] if len(parts) > 1 else text)
                if ref:
                    deps.append({"kind": "header", "name": name, "placeholder": ref})
            elif lower == "cookie":
                for cookie_name, cookie_value in _cookies(text):
                    ref = secrets.add(cookie_value)
                    if ref:
                        deps.append({"kind": "cookie", "name": cookie_name, "placeholder": ref})
            elif _sensitive(name):
                ref = secrets.add(text)
                if ref:
                    deps.append({"kind": "header", "name": name, "placeholder": ref})
        if call.get("url"):
            for name, value in parse_qsl(urlsplit(call["url"]).query, keep_blank_values=True):
                if _sensitive(name):
                    ref = secrets.add(value)
                    if ref:
                        deps.append({"kind": "query", "name": name, "placeholder": ref})
        body = _parse_json(call.get("post_data"))
        if body is not None:
            _walk_sensitive(body, secrets, deps)
        for gql_entry in _gql_entries(call):
            gql_payload = gql_entry.get("payload")
            if gql_payload and gql_payload.get("variables") is not None:
                _walk_sensitive(gql_payload.get("variables"), secrets, deps, "variables")
            query = gql_entry.get("query")
            if isinstance(query, str):
                for match in GQL_SECRET_ARG.finditer(query):
                    raw = match.group(2).strip()
                    value = raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"} else raw
                    ref = secrets.add(value)
                    if ref:
                        deps.append({"kind": "graphql-argument", "name": match.group(1), "placeholder": ref})
        response = _parse_json(_body_text(call))
        if response is not None:
            _walk_sensitive(response, secrets, [], response=True)
        for name, value in call["response_headers"].items():
            if name.lower() == "set-cookie":
                for _, cookie_value in _set_cookies(str(value)):
                    secrets.add(cookie_value)
            elif _sensitive(name):
                secrets.add(value)
        unique = {(d["kind"], d["name"].lower(), d["placeholder"]): d for d in deps}
        by_call[call["key"]] = [unique[k] for k in sorted(unique)]
    return secrets, by_call


def _schema(value: Any) -> dict[str, Any]:
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        return {"type": "array", "items": _merge_schema([_schema(v) for v in value]) if value else {}}
    if isinstance(value, dict):
        props = {str(k): _schema(v) for k, v in sorted(value.items(), key=lambda x: str(x[0]))}
        return {
            "type": "object",
            "properties": props,
            "additionalProperties": True,
            "x-uklok-observed-present": sorted(props),
        }
    return {}


def _merge_schema(values: list[dict[str, Any]]) -> dict[str, Any]:
    values = [v for v in values if v]
    if not values:
        return {}
    if len({json.dumps(v, sort_keys=True) for v in values}) == 1:
        return values[0]
    types = sorted({str(v.get("type")) for v in values if v.get("type")})
    if types == ["object"]:
        keys = sorted({k for v in values for k in (v.get("properties") or {})})
        props = {k: _merge_schema([v["properties"][k] for v in values if k in (v.get("properties") or {})]) for k in keys}
        observed_on_all = sorted(
            set.intersection(*[set((v.get("properties") or {}).keys()) for v in values])
        )
        return {
            "type": "object",
            "properties": props,
            "additionalProperties": True,
            "x-uklok-observed-present": keys,
            "x-uklok-observed-on-all": observed_on_all,
        }
    if types == ["array"]:
        return {"type": "array", "items": _merge_schema([v.get("items") or {} for v in values])}
    return {"type": types[0] if len(types) == 1 else types}


def _group(calls: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for call in calls:
        for identity in _identities(call):
            out.setdefault(identity["key"], []).append(call)
    return out


def _provenance(call: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_key": call["key"],
        "request_id": call["request_id"],
        "opening_seq": call["opening_seq"],
        "last_observed_seq": call["last_seq"],
        "redirects": call["redirects"],
        "attribution": call.get("owner_status") or ("attributed" if call.get("owner") else "unattributed"),
        "owner_candidates": sorted(set(call.get("owner_candidates") or [])),
    }


def _body_evidence(call: dict[str, Any]) -> dict[str, Any]:
    fact = call.get("body") or {}
    out = {"status": str(fact.get("status") or "unobserved")}
    for key in ("reason", "byte_length", "encoded_data_length"):
        if fact.get(key) is not None:
            out[key] = fact[key]
    return out


def _dependency_names(calls: list[dict[str, Any]], deps: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], set[str]] = {}
    for call in calls:
        for dependency in deps.get(call["key"], []):
            grouped.setdefault((dependency["kind"], dependency["name"]), set()).add(dependency["placeholder"])
    return [
        {"kind": kind, "name": name, "placeholders": sorted(grouped[(kind, name)])}
        for kind, name in sorted(grouped)
    ]


def _credential_rules(calls: list[dict[str, Any]], deps: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    call_by_key = {call["key"]: call for call in calls}
    all_calls = set(call_by_key)
    domains: dict[str, set[str]] = {}
    goals: dict[str, set[str]] = {}
    operations: dict[str, set[str]] = {}
    operation_memberships: dict[str, set[str]] = {}
    for call in calls:
        identities = _identities(call)
        operation_memberships[call["key"]] = {identity["key"] for identity in identities}
        domains.setdefault(identities[0]["host"], set()).add(call["key"])
        if call.get("owner"):
            goals.setdefault(str(call["owner"]), set()).add(call["key"])
        for identity in identities:
            operations.setdefault(identity["key"], set()).add(call["key"])

    occurrences: dict[tuple[str, str], set[str]] = {}
    placeholders: dict[tuple[str, str], set[str]] = {}
    for call in calls:
        for dependency in deps.get(call["key"], []):
            key = (dependency["kind"], dependency["name"])
            occurrences.setdefault(key, set()).add(call["key"])
            placeholders.setdefault(key, set()).add(dependency["placeholder"])

    rules: list[dict[str, Any]] = []
    for dep_key in sorted(occurrences):
        kind, name = dep_key
        remaining = set(occurrences[dep_key])

        def add_rule(scope: str, context: str, covered: set[str]) -> None:
            rules.append(
                {
                    "scope": scope,
                    "context": context,
                    "kind": kind,
                    "name": name,
                    "placeholders": sorted(placeholders[dep_key]),
                    "observed_calls": len(covered),
                    "observed_on_all_context_calls": True,
                }
            )

        if all_calls and all_calls <= remaining:
            add_rule("global", "*", all_calls)
            remaining -= all_calls
        else:
            for scope, contexts in (("domain", domains), ("operation", operations), ("goal", goals)):
                for context, context_calls in sorted(contexts.items()):
                    covered = context_calls
                    if scope == "operation":
                        # One physical GraphQL batch can represent several logical
                        # operations. Never let iteration order assign a transport-
                        # level credential to one arbitrary batch entry.
                        covered = {
                            request_key
                            for request_key in context_calls
                            if operation_memberships.get(request_key) == {context}
                        }
                    if covered and covered <= remaining:
                        add_rule(scope, context, covered)
                        remaining -= covered

        if remaining:
            rules.append(
                {
                    "scope": "partial",
                    "context": "observed-calls",
                    "kind": kind,
                    "name": name,
                    "placeholders": sorted(placeholders[dep_key]),
                    "request_keys": sorted(remaining),
                    "observed_on_all_context_calls": False,
                }
            )
    return rules


def _endpoint_records(calls: list[dict[str, Any]], deps: dict[str, list[dict[str, str]]], steps_by_key: dict[str, set[str]]) -> list[dict[str, Any]]:
    out = []
    for key, items in sorted(_group(calls).items()):
        ident = _identity_for_key(items[0], key)
        header_sets = [{h.lower(): h for h in c["request_headers"]} for c in items]
        all_headers = sorted(set.intersection(*[set(x) for x in header_sets])) if header_sets else []
        any_headers = sorted(set().union(*[set(x) for x in header_sets])) if header_sets else []
        query: dict[str, set[str]] = {}
        for call in items:
            for name, value in parse_qsl(urlsplit(str(call.get("url") or "")).query, keep_blank_values=True):
                kind = "boolean" if value.lower() in {"true", "false"} else "integer" if re.fullmatch(r"[-+]?\d+", value) else "number" if re.fullmatch(r"[-+]?\d+\.\d+", value) else "string"
                query.setdefault(name, set()).add(kind)
        out.append(
            {
                "key": key,
                "kind": ident["kind"],
                "method": ident["method"],
                "host": ident["host"],
                "path": ident["path"],
                "count": len(items),
                "steps": sorted({c["owner"] for c in items if c["owner"]}),
                "first_step": next(
                    (c["owner"] for c in sorted(items, key=lambda value: value["opening_seq"] if value["opening_seq"] is not None else 10**18) if c["owner"]),
                    None,
                ),
                "shared_across_steps": len(steps_by_key.get(key, set())) > 1,
                "request": {
                    "path_parameters": ident["path_params"],
                    "query_parameters": {k: sorted(v) for k, v in sorted(query.items())},
                    "headers": {"observed_on_all_calls": all_headers, "observed_on_any_call": any_headers},
                },
                "response": {
                    "statuses": sorted({str(c["status"]) for c in items if c["status"] is not None}),
                    "body_evidence": [_body_evidence(c) for c in items],
                    "sets_cookies": sorted({n for c in items for h, v in c["response_headers"].items() if h.lower() == "set-cookie" for n, _ in _set_cookies(str(v))}),
                },
                "credential_dependencies": _dependency_names(items, deps),
                "provenance": [_provenance(c) for c in items],
            }
        )
    return out


def _graphql(calls: list[dict[str, Any]], secrets: Secrets, generation: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records, models = [], []
    for key, items in sorted(_group(calls).items()):
        ident = _identity_for_key(items[0], key)
        if ident["kind"] != "graphql":
            continue
        docs, var_schemas, result_schemas = set(), [], []
        variants, persisted_hashes, reasons = set(), set(), set()
        parsed_states = []
        for call in items:
            matching = _identity_for_key(call, key)["gql"]
            parsed_states.append(bool(matching["parsed"]))
            variants.add(str(matching["variant"]))
            if matching.get("persisted_hash"):
                persisted_hashes.add(str(matching["persisted_hash"]))
            if matching.get("reason"):
                reasons.add(str(matching["reason"]))
            query = matching.get("query")
            if isinstance(query, str):
                docs.add(secrets.redact_graphql(query))
            payload = matching.get("payload")
            if isinstance(payload, dict) and payload.get("variables") is not None:
                var_schemas.append(_schema(payload["variables"]))
            result = _parse_json(_body_text(call))
            entry_index = matching.get("entry_index")
            if (
                matching.get("variant") == "json-batch"
                and isinstance(result, list)
                and isinstance(entry_index, int)
                and 0 <= entry_index < len(result)
            ):
                result = result[entry_index]
            if result is not None:
                result_schemas.append(_schema(result))
        parse_status = "parsed" if all(parsed_states) else "unparsed"
        record = {
            "key": key,
            "operation_name": ident["gql_name"],
            "host": ident["host"],
            "path": ident["path"],
            "method": ident["method"],
            "count": len(items),
            "parse_status": parse_status,
            "variants": sorted(variants),
            "documents": sorted(docs),
            "persisted_hashes": sorted(persisted_hashes),
            "unparsed_reasons": sorted(reasons),
            "observed_variables_schema": _merge_schema(var_schemas),
            "observed_result_schema": _merge_schema(result_schemas),
            "provenance": [_provenance(c) for c in items],
        }
        records.append(record)
        models.append({
            "operation_name": ident["gql_name"],
            "operation_key": key,
            "parse_status": parse_status,
            "variables": record["observed_variables_schema"],
            "result": record["observed_result_schema"],
        })
    return records, {
        "schema": "uklok.browser.graphql-observed-schema/v1",
        "generation": generation,
        "reader_fingerprint": _reader_fingerprint(),
        "complete": False,
        "authority": "observed-only",
        "note": "Observed captured operations only; not the server's authoritative GraphQL schema.",
        "operations": models,
    }


def _openapi(host: str, calls: list[dict[str, Any]], deps: dict[str, list[dict[str, str]]], generation: str) -> dict[str, Any]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    scheme = "https"
    for call in calls:
        for ident in _identities(call):
            if ident["host"] == host and ident["kind"] == "http":
                scheme = ident["scheme"]
                buckets.setdefault((ident["path"], ident["method"].lower()), []).append(call)
    paths = {}
    for (path, method), items in sorted(buckets.items()):
        ident = next(identity for identity in _identities(items[0]) if identity["kind"] == "http" and identity["host"] == host and identity["path"] == path and identity["method"].lower() == method)
        params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in ident["path_params"]]
        query_names = sorted({n for c in items for n, _ in parse_qsl(urlsplit(str(c.get("url") or "")).query, keep_blank_values=True)})
        params.extend(
            {
                "name": n,
                "in": "query",
                "required": False,
                "schema": {"type": "string"},
                "x-uklok-observed-on-all-calls": all(
                    n in {q for q, _ in parse_qsl(urlsplit(str(c.get("url") or "")).query, keep_blank_values=True)}
                    for c in items
                ),
            }
            for n in query_names
        )
        request_schemas = [_schema(v) for c in items for v in [_parse_json(c.get("post_data"))] if v is not None]
        statuses = sorted({str(c["status"]) for c in items if c["status"] is not None}) or ["default"]
        responses = {}
        for status in statuses:
            matched = items if status == "default" else [c for c in items if str(c["status"]) == status]
            schemas = [_schema(v) for c in matched for v in [_parse_json(_body_text(c))] if v is not None]
            response = {"description": "Observed response", "x-uklok-body-evidence": [_body_evidence(c) for c in matched]}
            if schemas:
                response["content"] = {"application/json": {"schema": _merge_schema(schemas)}}
            responses[status] = response
        op = {
            "summary": "Observed operation",
            "parameters": params,
            "responses": responses,
            "x-uklok-observed-count": len(items),
            "x-uklok-credential-dependencies": _dependency_names(items, deps),
            "x-uklok-provenance": [_provenance(c) for c in items],
        }
        if request_schemas:
            op["requestBody"] = {"content": {"application/json": {"schema": _merge_schema(request_schemas)}}}
        gql_names = sorted({_identity(c).get("gql_name") for c in items if _identity(c)["kind"] == "graphql"})
        if gql_names:
            op["x-uklok-graphql-operations"] = gql_names
        paths.setdefault(path, {})[method] = op
    return {
        "openapi": "3.1.0",
        "info": {"title": f"Observed API surface for {host}", "version": "observed", "description": "Observed browser traffic only; not a completeness claim."},
        "servers": [{"url": f"{scheme}://{host}"}],
        "paths": paths,
        "x-uklok-observed-only": True,
        "x-uklok-generation": generation,
    }


def _safe(root: Path, *parts: str) -> Path:
    root = root.resolve()
    target = root.joinpath(*parts).resolve()
    if target != root and root not in target.parents:
        raise OperationReadError(f"derived path escaped run directory: {target}")
    return target


def _write(run: Path, relative: str, value: Any) -> None:
    path = _safe(run, *Path(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _step_dirs(run: Path) -> dict[str, Path]:
    out = {}
    for directory in sorted((run / "steps").glob("*")) if (run / "steps").is_dir() else []:
        checkpoint = directory / "checkpoint.json"
        try:
            value = json.loads(checkpoint.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value.get("step"), str):
            out[value["step"]] = directory
    return out


def _secret_store(run: Path, secrets: Secrets, generation: str) -> None:
    path = _safe(run, "traffic", "secrets.env")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# uklok-operation-generation: {generation}"]
    lines.extend(
        f"UKLOK_SECRET_{i:03d}={json.dumps(v, ensure_ascii=False)}"
        for i, v in enumerate(secrets.values, 1)
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _secret_generation(run: Path) -> str | None:
    path = run / "traffic" / "secrets.env"
    if not path.is_file():
        return None
    prefix = "# uklok-operation-generation:"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            return value or None
    return None


def _secret_values(run: Path) -> list[str]:
    path = run / "traffic" / "secrets.env"
    values = []
    if path.is_file():
        for line in path.read_text().splitlines():
            if "=" in line:
                try:
                    value = json.loads(line.split("=", 1)[1])
                except json.JSONDecodeError:
                    continue
                if isinstance(value, str):
                    values.append(value)
    return values


SECRET_NAME_FIELDS = {
    "name",
    "operation_name",
    "host",
    "method",
    "kind",
    "schema",
    "scope",
    "context",
    "authority",
    "step",
    "type",
    "in",
    "status",
    "reason",
    "summary",
    "description",
    "title",
    "key",
    "request_key",
    "request_id",
    "request_keys",
    "observed_on_all_calls",
    "observed_on_any_call",
    "path_parameters",
    "sets_cookies",
    "owner_candidates",
    "variants",
}


def _string_values(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, list):
        return [item for child in value for item in _string_values(child, path)]
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in _string_values(child, path + (str(key),))]
    return []


def _graphql_secret_literal(text: str, secret: str) -> bool:
    for match in GQL_IDENTITY_LITERAL.finditer(text):
        raw = match.group(0)
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                value = raw[1:-1]
        else:
            value = raw
        if str(value) == secret:
            return True
    return False


def _host_filename(host: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._-") or "host"
    # Keep the readable stem bounded while the full digest owns uniqueness.
    stem = stem[:120]
    digest = hashlib.sha256(host.encode()).hexdigest()
    return f"{stem}-{digest}.json"


def _reader_fingerprint() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:20]


def _generation_id(run: Path, selected: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(_reader_fingerprint().encode())
    digest.update(b"\0")
    for relative in ("traffic/events.jsonl", "traffic/checkpoints.jsonl"):
        path = run / relative
        if not path.is_file():
            raise OperationReadError(f"missing required traffic evidence: {path}")
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    digest.update(json.dumps(selected, sort_keys=True).encode())
    return digest.hexdigest()[:20]


def _artifact_generation(value: dict[str, Any]) -> str | None:
    generation = value.get("generation")
    if isinstance(generation, str):
        return generation
    generation = value.get("x-uklok-generation")
    return generation if isinstance(generation, str) else None

def verify_reading(run: Path) -> None:
    index_path = run / "operations" / "index.json"
    if not index_path.is_file():
        raise OperationReadError("derived index is missing")
    index = json.loads(index_path.read_text())
    expected_generation = index.get("generation")
    if not isinstance(expected_generation, str) or not expected_generation:
        raise OperationReadError("derived index has no generation identity")
    reader_fingerprint = index.get("reader_fingerprint")
    if not isinstance(reader_fingerprint, str) or not reader_fingerprint:
        raise OperationReadError("derived index has no reader fingerprint")

    secret_generation = _secret_generation(run)
    if secret_generation != expected_generation:
        raise OperationReadError("mixed or missing generation identity: traffic/secrets.env")

    secrets = _secret_values(run)
    files = list((run / "operations").rglob("*.json")) if (run / "operations").is_dir() else []
    files += [p for d in (run / "steps").glob("*/operations") for p in d.rglob("*.json")] if (run / "steps").is_dir() else []
    for path in files:
        value = json.loads(path.read_text())
        if _artifact_generation(value) != expected_generation:
            raise OperationReadError(f"mixed or missing generation identity: {path}")
        for string_path, text in _string_values(value):
            field = string_path[-1] if string_path else ""
            for secret in secrets:
                if field == "documents":
                    if _graphql_secret_literal(text, secret):
                        raise OperationReadError(f"secret survived in derived artifact: {path}")
                    continue
                if field in SECRET_NAME_FIELDS:
                    continue
                if text == secret or (len(secret) >= 12 and secret in text):
                    raise OperationReadError(f"secret survived in derived artifact: {path}")


def derive_operations(run: Path, step: str | None = None) -> dict[str, Any]:
    run = run.resolve()
    if not run.is_dir():
        raise OperationReadError(f"run directory does not exist: {run}")
    assembled, boundaries = _assemble(run)
    calls = [call for call in assembled if _api(call)]
    secrets, deps = _collect(calls)
    credential_rules = _credential_rules(calls, deps)
    grouped = _group(calls)
    steps_by_key = {key: {c["owner"] for c in items if c["owner"]} for key, items in grouped.items()}
    known_steps = {b["step"] for b in boundaries}
    if step is not None and step not in known_steps:
        raise OperationReadError(f"unknown captured step: {step}")
    dirs = _step_dirs(run)
    selected = [step] if step is not None else sorted(known_steps)
    generation = _generation_id(run, selected)

    operation_counts = {key: len(items) for key, items in sorted(grouped.items())}
    covered_call_keys = {call["key"] for items in grouped.values() for call in items}
    index = {
        "schema": "uklok.browser.operation-index/v1",
        "generation": generation,
        "reader_fingerprint": _reader_fingerprint(),
        "complete": False,
        "authority": "observed-only",
        "scope": {
            "kind": "step" if step is not None else "run",
            "selected_steps": selected,
            "invalidated_steps": sorted(known_steps - set(selected)),
        },
        "total_observed_calls": len(calls),
        "logical_operation_observations": sum(operation_counts.values()),
        "attributed_count": sum(bool(c["owner"]) for c in calls),
        "unattributed_count": sum(not c["owner"] for c in calls),
        "operation_counts": operation_counts,
        "operation_keys": sorted(operation_counts),
        "credential_rules": credential_rules,
        "unattributed": [_provenance(c) for c in calls if not c["owner"]],
        "steps": {},
        "integrity": {
            "assembled_api_calls": len(calls),
            "grouped_call_count": len(covered_call_keys),
            "logical_operation_count": sum(operation_counts.values()),
            "reconciles": len(covered_call_keys) == len(calls),
        },
    }
    for step_id in sorted(known_steps):
        step_calls = [c for c in calls if c["owner"] == step_id]
        keys = sorted(_group(step_calls))
        index["steps"][step_id] = {
            "generation": generation if step_id in selected else None,
            "artifact_status": "published" if step_id in selected else "invalidated",
            "total_observed_calls": len(step_calls),
            "grouped_operation_count": len(keys),
            "operation_keys": keys,
            "distinct_operations": [k for k in keys if len(steps_by_key.get(k, set())) == 1],
            "shared_operations": [k for k in keys if len(steps_by_key.get(k, set())) > 1],
            "credential_dependencies": _dependency_names(step_calls, deps),
        }

    stage = _safe(run, f".operations-stage-{generation}")
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    try:
        _write(stage, "operations/index.json", index)
        _secret_store(stage, secrets, generation)

        for step_id in selected:
            directory = dirs.get(step_id)
            if not directory:
                continue
            step_calls = [c for c in calls if c["owner"] == step_id]
            base = directory.relative_to(run) / "operations"
            keys = sorted(_group(step_calls))
            _write(stage, str(base / "endpoints.json"), {
                "schema": "uklok.browser.operation-reading/v1",
                "generation": generation,
                "step": step_id,
                "operations": _endpoint_records(step_calls, deps, steps_by_key),
            })
            step_dependencies = _dependency_names(step_calls, deps)
            _write(
                stage,
                str(base / "auth.json"),
                {
                    "schema": "uklok.browser.operation-auth/v1",
                    "generation": generation,
                    "step": step_id,
                    "dependencies": step_dependencies,
                },
            )
            _write(stage, str(base / "goal.json"), {
                "schema": "uklok.browser.operation-goal/v1",
                "generation": generation,
                "step": step_id,
                "total_observed_calls": len(step_calls),
                "grouped_operation_count": len(keys),
                "operation_keys": keys,
                "distinct_operations": [k for k in keys if len(steps_by_key.get(k, set())) == 1],
                "shared_operations": [k for k in keys if len(steps_by_key.get(k, set())) > 1],
                "shared_with": {k: sorted(steps_by_key[k] - {step_id}) for k in keys if len(steps_by_key.get(k, set())) > 1},
            })
            gql, model = _graphql(step_calls, secrets, generation)
            _write(stage, str(base / "graphql" / "operations.json"), {
                "schema": "uklok.browser.graphql-operations/v1",
                "generation": generation,
                "step": step_id,
                "operations": gql,
            })
            _write(stage, str(base / "graphql" / "observed-schema.json"), model)
            hosts = {
                identity["host"]
                for call in step_calls
                for identity in _identities(call)
                if identity["kind"] == "http"
            }
            for host in sorted(hosts):
                _write(stage, str(base / "openapi" / _host_filename(host)), _openapi(host, step_calls, deps, generation))

        if not index["integrity"]["reconciles"]:
            raise OperationReadError("operation counts did not reconcile")
        verify_reading(stage)

        # Publish only after the complete staged generation passes every gate.
        # Remove the old commit marker first, keep all previous artifacts hidden
        # as rollback state, and move the new index last.
        backup = stage / ".previous"
        published_index = run / "operations"
        published_secrets = run / "traffic" / "secrets.env"
        published_secrets.parent.mkdir(parents=True, exist_ok=True)
        backed_up_index = False
        backed_up_secrets = False
        backed_up_steps: list[Path] = []
        new_index_published = False
        new_secrets_published = False
        new_steps_published: list[Path] = []
        try:
            if published_index.exists():
                target = backup / "operations"
                target.parent.mkdir(parents=True, exist_ok=True)
                published_index.replace(target)
                backed_up_index = True

            for step_id, directory in dirs.items():
                target = directory / "operations"
                if target.exists():
                    previous = backup / directory.relative_to(run) / "operations"
                    previous.parent.mkdir(parents=True, exist_ok=True)
                    target.replace(previous)
                    backed_up_steps.append(directory)

            if published_secrets.exists():
                previous_secrets = backup / "traffic" / "secrets.env"
                previous_secrets.parent.mkdir(parents=True, exist_ok=True)
                published_secrets.replace(previous_secrets)
                backed_up_secrets = True

            for step_id, directory in dirs.items():
                if step_id not in selected:
                    continue
                source = stage / directory.relative_to(run) / "operations"
                if source.exists():
                    source.replace(directory / "operations")
                    new_steps_published.append(directory)

            staged_secrets = stage / "traffic" / "secrets.env"
            staged_secrets.replace(published_secrets)
            new_secrets_published = True
            try:
                published_secrets.chmod(0o600)
            except OSError:
                pass

            (stage / "operations").replace(published_index)
            new_index_published = True
            verify_reading(run)
        except Exception:
            if new_index_published:
                shutil.rmtree(published_index, ignore_errors=True)
            for directory in new_steps_published:
                shutil.rmtree(directory / "operations", ignore_errors=True)
            if new_secrets_published and published_secrets.exists():
                published_secrets.unlink()

            previous_index = backup / "operations"
            if backed_up_index and previous_index.exists():
                previous_index.replace(published_index)
            for directory in backed_up_steps:
                previous = backup / directory.relative_to(run) / "operations"
                if previous.exists():
                    previous.replace(directory / "operations")
            previous_secrets = backup / "traffic" / "secrets.env"
            if backed_up_secrets and previous_secrets.exists():
                previous_secrets.replace(published_secrets)
            raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return index

