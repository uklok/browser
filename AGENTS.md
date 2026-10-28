# UKLOK Browser — agent entrypoint

This repository inherits organization working rules from:

<https://github.com/uklok/ai-exchange/blob/main/AGENTS.md>

Read that entrypoint as the authority for issue → branch → review, evidence, attribution, and skill selection. This file adds only **browser-repository-specific** guidance.

## First 60 seconds

1. Open the assigned issue/PR and identify the concrete outcome.
2. Use [README.md](README.md) to choose the relevant task path.
3. For runtime, Docker, CDP/noVNC, profile, platform, or browser-startup work, load [browser-runtime](.agents/skills/browser-runtime/SKILL.md).
4. Read only the task-specific page under [docs/](docs/README.md); do not ingest the entire documentation set by default.
5. Prove the user-visible/runtime claim, not merely file validity.

## Repo invariants

Treat these as current implementation constraints unless the task explicitly changes them:

- one **headful** Chrome process is shared by human noVNC and agent CDP;
- base Compose publishes no host ports;
- current image target is `linux/amd64`;
- production keeps Chrome sandbox enabled with no automatic fallback;
- the local overlay may retry with `--no-sandbox` only after the known namespace failure;
- `/data/chrome` is a Linux-container-owned browser identity;
- macOS/Windows Chrome profiles are not authentication-portable into this Linux browser;
- bind-mounted non-empty profiles require an explicit UKLOK marker or intentional adoption;
- stale Chrome `Singleton*` artifacts are startup debris, not durable identity;
- accepted image publication is separate from documentation/Compose-only changes.

## Where truth lives

| Question | Source |
| --- | --- |
| What should the user run? | `docs/quickstart.md` |
| How does the system fit together? | `docs/architecture.md` |
| What owns login/session state? | `docs/profiles.md` |
| What is safe to expose/weaken? | `docs/security.md` |
| How do I diagnose runtime failures? | `docs/operations.md` |
| When/how is an image published? | `docs/releases.md` |
| What proves runtime acceptance? | `tests/smoke.sh` + workflow restart smoke |
| How should an agent reason about this runtime? | `.agents/skills/browser-runtime/SKILL.md` |

Do not duplicate these rules into new files. Update the natural owner and repair inbound links when the contract changes.

## Merge gate

Before claiming a runtime change complete:

- relevant review threads are resolved;
- the actual browser path was exercised or the missing proof is named precisely;
- CDP and noVNC are not confused with Chrome health;
- profile lifecycle is tested when identity behavior changes;
- docs/rules are updated when a discovered invariant changes;
- human approval exists before merge.
