---
name: browser-runtime
description: >-
  Use when building, deploying, debugging, or changing UKLOK Browser runtime
  behavior: Chrome startup, Xvfb/noVNC, CDP, Docker platform/sandbox behavior,
  persistent browser identity, or profile lifecycle.
metadata:
  title: Browser runtime
---

# Browser runtime

Prove the browser from the inside out. noVNC, CDP, Chrome, and profile identity are related but **not interchangeable signals**.

## Runtime model

One headful Chrome owns both surfaces:

```text
human -> noVNC -> x11vnc -> Xvfb -> Chrome
agent -> CDP relay ----------------> Chrome
```

A noVNC page can work while Chrome is dead. A running container can be unhealthy.

## Diagnostic order

1. **Container health** — inspect Docker health before interpreting UI.
2. **Chrome** — confirm the process survived startup.
3. **CDP** — `/json/version` must answer.
4. **Display** — Xvfb must be alive.
5. **noVNC** — verify the human surface.
6. **Profile** — only then reason about persistence/authentication.

When the screen is black but VNC connects, inspect Chrome logs before changing VNC.

## Apple-Silicon / platform rule

The image is currently `linux/amd64`.

Do not remove the Dockerfile amd64 guard to “support” an arm64 host. Select `linux/amd64` at the Compose/build boundary so Docker Desktop can emulate the intended image.

Native arm64 requires a verified browser-distribution path and its own runtime proof.

## Sandbox rule

Base/production:

```text
sandbox ON
automatic fallback OFF
```

Local overlay:

1. attempt sandboxed Chrome;
2. only when startup reports `Failed to move to new namespace`;
3. retry with `--no-sandbox`.

Do not generalize that fallback to arbitrary Chrome failures. Do not silently make production inherit it.

## Profile rule

`/data/chrome` is a durable **Linux Chrome identity**.

Do not bind a macOS/Windows Chrome user-data-dir into it expecting authenticated sessions to survive. Cross-platform copies can preserve tabs/history while losing encrypted authentication state.

For host-backed persistence:

- use an empty dedicated directory;
- let UKLOK Browser mark it;
- authenticate once inside the Linux Chrome session;
- keep that same profile across restarts.

A non-empty unmanaged bind should be rejected unless the user explicitly transfers ownership of a same-platform profile.

## ProcessSingleton rule

If a managed profile survives container recreation, stale:

```text
SingletonLock
SingletonCookie
SingletonSocket
```

may refer to the dead container. Clearing those before startup is valid for the managed, exclusively-owned profile.

It is **not** permission to run two Chrome instances against one user-data-dir.

## Proof matrix

| Claim | Proof |
| --- | --- |
| Chrome is alive | process + healthy CDP |
| Browser is headful | Xvfb alive and Chrome lacks `--headless` |
| Human surface works | noVNC endpoint + VNC session |
| Agent surface works | CDP `/json/version` |
| Profile persists | authenticated state survives stop/recreate |
| Lock handling works | same profile restarts without “profile in use” dialog |
| Local fallback is bounded | sandbox attempted first; fallback only on known namespace error |
| Production stays hardened | fallback remains disabled in base Compose |

Use `tests/smoke.sh` for the mechanical runtime contract, then add targeted proof when the task changes profile/security/lifecycle semantics.

## Preserve the lesson, not the incident

When a new runtime failure teaches a durable constraint:

1. fix the natural owner in code/config;
2. update the smallest relevant page under `docs/`;
3. update this skill only if the diagnostic/rule should guide future runtime work;
4. avoid preserving the entire debugging transcript as doctrine.
