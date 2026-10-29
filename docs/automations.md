# Browser automations

Browser Use gives UKLOK powerful browser primitives. The automation layer turns repeatedly learned browser behavior into **small deterministic programs** so an agent is not required for every run.

## Model

~~~text
scheduler / human
      │
      ▼
browser-automation run
      │
      ├── reads contract.toml
      │      intent
      │      authority
      │      pseudocode
      │      checkpoints
      │      resume semantics
      │
      ├── executes run.py step_<id>() functions
      │      in contract order
      │
      ▼
Browser Use CLI ──► UKLOK Chrome/CDP

checkpoint passes ──► continue deterministically

checkpoint fails
      │
      ▼
.runs/.../failure.json
      │
      ▼
agent loads browser-automation skill
      │
      ├── starts at exact failed checkpoint
      ├── explores only when needed
      ├── updates contract behavior first
      └── updates the matching module step
~~~

The contract is the knowledge layer. Python is not allowed to become a second description of what the automation means.

## Why this shape

A browser agent is excellent at exploration and adaptation but expensive and unnecessarily variable for behavior we already understand.

Once a path is learned:

1. describe the intention as pseudocode;
2. name observable checkpoints;
3. encode only those steps deterministically;
4. run without an agent;
5. invoke an agent only when reality no longer satisfies a checkpoint;
6. preserve the newly learned behavior in the contract.

Repeated work therefore trends from agent-heavy exploration toward cheap deterministic execution.

## Create an automation

After `./bin/browser-use-setup`:

~~~bash
./bin/browser-automation new upwork_example
~~~

This creates:

~~~text
automations/upwork_example/
├── contract.toml
└── run.py
~~~

Write `contract.toml` **before** implementation.

### Contract shape

Every contract uses:

~~~toml
schema = "uklok.browser.automation/v1"
id = "upwork_example"
version = 1
status = "draft"
intent = "One observable outcome."
module = "run.py"

[trigger]
description = "When this should execute."

[authority]
allowed = ["Actions already authorized for unattended execution."]
forbidden = ["Actions this automation must never take silently."]

[[inputs]]
name = "example"
type = "string"
required = true
sensitive = false
description = "Meaning of this input."

[[preconditions]]
id = "session_ready"
condition = "Required browser identity/session already exists."

[[algorithm]]
id = "find_target"
pseudocode = """
OPEN the relevant page.
LOCATE the target using stable page state.
STOP if the state cannot be established.
"""
checkpoint = "The target is observably present."
on_failure = "Stop before any later action."
resume = "safe"
known_variants = []

[success]
condition = "Observable final state."

[failure]
capture_screenshot = true
agent_skill = ".agents/skills/browser-automation/SKILL.md"
~~~

### Implementation shape

Each algorithm step has exactly one synchronous implementation:

~~~python
def step_find_target(ctx):
    observed = js("document.title")
    return {
        "ok": bool(observed),
        "observed": {"title": observed},
    }
~~~

The runner validates that contract step IDs and Python `step_<id>()` functions match exactly. Extra hidden steps or missing implementations fail validation.

## Validate

~~~bash
./bin/browser-automation validate
./bin/browser-automation validate upwork_example
~~~

Validation checks contract shape, module syntax and exact step/function alignment.

A `draft` contract can validate, but only `status = "ready"` automations may run.

## Run

~~~bash
./bin/browser-automation run example_read_page
~~~

Inputs are explicit:

~~~bash
./bin/browser-automation run example_read_page \
  --input url=https://example.com
~~~

The runner acquires the single shared browser-lane lock, then feeds the deterministic module through the repo-local Browser Use CLI connected to the existing UKLOK Chrome.

No LLM/agent is loaded.

## Checkpoints

Before each step the runtime writes local state. After a passing step it writes an event containing the observed evidence.

A step continues only when its implementation returns:

~~~python
{"ok": True, "observed": {...}}
~~~

Anything else is a failed checkpoint. Later steps do not execute after a mismatch.

## Failure handoff

Failures live under `.runs/`, which is intentionally gitignored.

`failure.json` contains:

- automation and run IDs;
- exact failed checkpoint;
- contract pseudocode and expected state;
- known variants;
- observed result;
- exception when one occurred;
- current browser/tab/page information when available;
- screenshot path when capture succeeds;
- contract and module paths;
- exact `step_<id>()` function;
- safe restart/resume instruction;
- `.agents/skills/browser-automation/SKILL.md` as the agent entrypoint.

That keeps agent startup narrow: it does not have to rediscover the entire automation or repository.

## Resume

A contract step explicitly declares `resume = "safe"` or `resume = "restart"`.

When safe:

~~~bash
./bin/browser-automation run <id> --from <checkpoint> ...
~~~

The runner rejects `--from` for a restart-only checkpoint.

This is a contract assertion, not a convenience flag. Mark a step safe only when previous state can legitimately be assumed from the current browser session.

## Repair

For a failed automation:

1. give the agent the emitted `failure.json`;
2. load the [browser-automation skill](../.agents/skills/browser-automation/SKILL.md);
3. inspect only the failed contract step + matching module function first;
4. load Browser Use's generated skill only when live browser exploration is necessary;
5. update contract knowledge before implementation behavior;
6. validate;
7. retry from the checkpoint only when `resume = "safe"`;
8. prove final success.

The repair artifact is the new contract/module behavior committed to Git. `.runs/` is transient evidence, not permanent doctrine.

## Example

`automations/example_read_page/` is deliberately read-only except for opening a public tab. It proves the contract/module/run/failure path without depending on an authenticated site.

~~~bash
./bin/browser-automation run example_read_page
~~~

## Boundaries

This layer does **not**:

- replace Browser Use interaction knowledge;
- replace the browser runtime;
- put an agent into successful routine runs;
- infer permission beyond `[authority]`;
- make one Chrome identity safely parallel.

When Chrome/CDP itself is unhealthy, switch to [Operations](operations.md) and the `browser-runtime` skill rather than teaching an automation to work around broken infrastructure.
