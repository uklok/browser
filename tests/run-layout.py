#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "uklok_automation_execute_layout",
    ROOT / "automations" / "_runtime" / "execute.py",
)
assert SPEC is not None and SPEC.loader is not None
execute = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(execute)


with tempfile.TemporaryDirectory() as raw_tmp:
    temp_root = Path(raw_tmp)
    physical_root = temp_root / "physical-run-root"
    physical_root.mkdir()
    root = temp_root / "run-root-alias"
    root.symlink_to(physical_root, target_is_directory=True)

    step_dir = execute._step_workspace(root, 2, "submit_proposal")
    assert step_dir == root / "steps" / "02-submit_proposal"
    assert step_dir.is_dir()

    canonical_step_dir = step_dir.resolve()
    assert canonical_step_dir != step_dir
    ctx = {
        "automation": "layout_test",
        "step_dir": str(step_dir),
        "run_dir": str(step_dir),
        "run_root": str(root),
    }

    assert execute._artifact_path(ctx, "invitation.json") == canonical_step_dir / "invitation.json"
    assert execute._artifact_path(ctx, "/tmp/open_apply.png") == canonical_step_dir / "open_apply.png"
    assert (
        execute._artifact_path(ctx, "details/response.json")
        == canonical_step_dir / "details" / "response.json"
    )

    try:
        execute._artifact_path(ctx, "../escape.json")
    except ValueError:
        pass
    else:
        raise AssertionError("step artifacts must not escape their checkpoint directory")

    outside_dir = temp_root / "outside"
    outside_dir.mkdir()
    escape_link = step_dir / "escape-link"
    escape_link.symlink_to(outside_dir, target_is_directory=True)

    try:
        execute._artifact_path(ctx, "escape-link/leak.json")
    except ValueError:
        pass
    else:
        raise AssertionError("symlinked step artifacts must not escape their checkpoint directory")

    screenshot_calls = []

    def fake_screenshot(path, *args, **kwargs):
        screenshot_calls.append((Path(path), args, kwargs))
        return path

    module = root / "run.py"
    module.write_text(
        "def step_capture(ctx):\n"
        "    return {'ok': True, 'observed': capture_screenshot('/tmp/open_home.png', full=False)}\n",
        encoding="utf-8",
    )
    namespace = execute._load_module(module, {"capture_screenshot": fake_screenshot}, ctx)
    result = namespace["step_capture"](ctx)
    assert result["ok"] is True
    assert screenshot_calls[0][0] == canonical_step_dir / "open_home.png"

print("run layout validation passed")
