from __future__ import annotations

import datetime as dt
import json
import os
import tomllib
import traceback
from pathlib import Path
from typing import Any


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _append_event(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True, default=str) + "\n")


def _browser_snapshot(browser: dict[str, Any], capture_screenshot: bool) -> dict[str, Any]:
    snapshot: dict[str, Any] = {}

    current_tab = browser.get("current_tab")
    if callable(current_tab):
        try:
            snapshot["tab"] = _safe(current_tab())
        except Exception as exc:
            snapshot["tab_error"] = str(exc)

    page_info = browser.get("page_info")
    if callable(page_info):
        try:
            snapshot["page_info"] = _safe(page_info())
        except Exception as exc:
            snapshot["page_info_error"] = str(exc)

    if capture_screenshot:
        screenshot = browser.get("capture_screenshot")
        if callable(screenshot):
            try:
                snapshot["screenshot"] = str(screenshot(full=False))
            except Exception as exc:
                snapshot["screenshot_error"] = str(exc)

    return snapshot


def _load_module(module_path: Path, browser: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    namespace: dict[str, Any] = {
        "__builtins__": __builtins__,
        "__file__": str(module_path),
        "__name__": f"uklok_automation_{ctx['automation']}",
        "ctx": ctx,
    }
    for name, value in browser.items():
        if not name.startswith("__"):
            namespace[name] = value
    source = module_path.read_text(encoding="utf-8")
    exec(compile(source, str(module_path), "exec"), namespace, namespace)
    return namespace


def _failure(
    *,
    payload: dict[str, Any],
    contract: dict[str, Any],
    step: dict[str, Any],
    failure_type: str,
    observed: Any,
    error: str | None,
    browser: dict[str, Any],
) -> Path:
    run_dir = Path(payload["run_dir"])
    failure_policy = contract.get("failure", {})
    browser_state = _browser_snapshot(browser, bool(failure_policy.get("capture_screenshot", True)))
    step_id = step["id"]
    resume = step["resume"]

    failure = {
        "schema": "uklok.browser.automation-failure/v1",
        "automation": payload["automation"],
        "run_id": run_dir.name,
        "type": failure_type,
        "failed_at": _now(),
        "checkpoint": step_id,
        "expected": step["checkpoint"],
        "pseudocode": step["pseudocode"],
        "known_variants": step.get("known_variants", []),
        "on_failure": step["on_failure"],
        "resume": resume,
        "observed": _safe(observed),
        "error": error,
        "browser": browser_state,
        "contract": str(Path(payload["contract_path"]).relative_to(payload["root"])),
        "module": str(Path(payload["module_path"]).relative_to(payload["root"])),
        "function": f"step_{step_id}",
        "inputs": payload["recorded_inputs"],
        "traffic": payload.get("traffic"),
        "agent_entrypoint": failure_policy.get("agent_skill", ".agents/skills/browser-automation/SKILL.md"),
        "repair_scope": {
            "start_here": [
                "this failure.json",
                "the failed [[algorithm]] step in contract.toml",
                f"step_{step_id}() in run.py",
            ],
            "rerun": (
                f"./bin/browser-automation run {payload['automation']} --from {step_id}"
                if resume == "safe"
                else f"./bin/browser-automation run {payload['automation']}"
            ),
        },
    }
    path = run_dir / "failure.json"
    _write_json(path, failure)
    return path


def execute_from_env(browser: dict[str, Any]) -> None:
    raw = os.environ.get("UKLOK_AUTOMATION_PAYLOAD")
    if not raw:
        raise RuntimeError("UKLOK_AUTOMATION_PAYLOAD is missing")
    payload = json.loads(raw)

    contract_path = Path(payload["contract_path"])
    module_path = Path(payload["module_path"])
    run_dir = Path(payload["run_dir"])
    contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = contract["algorithm"]

    from_step = payload.get("from_step")
    if from_step:
        index = next(index for index, step in enumerate(steps) if step["id"] == from_step)
        steps = steps[index:]

    ctx: dict[str, Any] = {
        "automation": payload["automation"],
        "inputs": payload["inputs"],
        "run_dir": str(run_dir),
        "contract": {
            "id": contract["id"],
            "version": contract["version"],
            "intent": contract["intent"],
            "authority": contract["authority"],
        },
        "step": None,
    }

    namespace = _load_module(module_path, browser, ctx)
    events_path = run_dir / "events.ndjson"
    completed: list[str] = []

    for step in steps:
        step_id = step["id"]
        ctx["step"] = step
        _write_json(
            run_dir / "state.json",
            {
                "automation": payload["automation"],
                "run_id": run_dir.name,
                "status": "running",
                "current_step": step_id,
                "completed": completed,
                "updated_at": _now(),
            },
        )
        _append_event(
            events_path,
            {
                "event": "step_started",
                "step": step_id,
                "at": _now(),
                "checkpoint": step["checkpoint"],
            },
        )

        fn = namespace[f"step_{step_id}"]
        try:
            result = fn(ctx)
        except Exception:
            error = traceback.format_exc()
            path = _failure(
                payload=payload,
                contract=contract,
                step=step,
                failure_type="exception",
                observed=None,
                error=error,
                browser=browser,
            )
            _append_event(events_path, {"event": "step_failed", "step": step_id, "at": _now(), "failure": str(path)})
            raise RuntimeError(f"automation failed at {step_id}; handoff: {path}") from None

        if not isinstance(result, dict) or result.get("ok") is not True:
            observed = result.get("observed") if isinstance(result, dict) else result
            path = _failure(
                payload=payload,
                contract=contract,
                step=step,
                failure_type="checkpoint",
                observed=observed,
                error=None,
                browser=browser,
            )
            _append_event(events_path, {"event": "checkpoint_failed", "step": step_id, "at": _now(), "failure": str(path)})
            raise RuntimeError(f"checkpoint failed at {step_id}; handoff: {path}")

        completed.append(step_id)
        _append_event(
            events_path,
            {
                "event": "checkpoint_passed",
                "step": step_id,
                "at": _now(),
                "observed": _safe(result.get("observed")),
                "evidence": _safe(result.get("evidence")),
            },
        )

    result = {
        "schema": "uklok.browser.automation-result/v1",
        "automation": payload["automation"],
        "run_id": run_dir.name,
        "status": "succeeded",
        "completed_at": _now(),
        "completed_checkpoints": completed,
        "success_condition": contract["success"]["condition"],
        "traffic": payload.get("traffic"),
    }
    _write_json(run_dir / "result.json", result)
    _write_json(
        run_dir / "state.json",
        {
            "automation": payload["automation"],
            "run_id": run_dir.name,
            "status": "succeeded",
            "current_step": None,
            "completed": completed,
            "updated_at": _now(),
        },
    )
