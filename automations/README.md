# Browser automations

This directory is the contract-first knowledge layer over Browser Use.

A tracked automation lives at:

~~~text
automations/<id>/
├── contract.toml   intention, authority, pseudocode, checkpoints
└── run.py          deterministic reflection of those steps
~~~

Infrastructure shared by every automation stays under `_runtime/`; `_template/` is the scaffold source.

## Commands

~~~bash
./bin/browser-automation list
./bin/browser-automation new <id>
./bin/browser-automation validate [<id>]
./bin/browser-automation run <id> --input key=value
~~~

When a run fails, the runtime writes a local, gitignored:

~~~text
.runs/<id>/<run-id>/failure.json
~~~

That file is the agent repair entrypoint. It points directly to the failed contract checkpoint and `step_<id>()`.

See [Browser automations](../docs/automations.md) for the operating model and [.agents/skills/browser-automation/SKILL.md](../.agents/skills/browser-automation/SKILL.md) for agent repair behavior.
