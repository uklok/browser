# Architecture

## One browser, two control surfaces

```text
                         Docker network
┌─────────────────────────────────────────────────────────────┐
│ browser container                                           │
│                                                             │
│  Xvfb :99 ──► Openbox ──► Google Chrome (headful)           │
│                              │                              │
│                              ├─ CDP 127.0.0.1:9223          │
│                              │        │                     │
│                              │      socat ──► :9222         │
│                              │                              │
│                              └─ X framebuffer               │
│                                     │                       │
│                                  x11vnc                     │
│                              127.0.0.1:5900                 │
│                                     │                       │
│                             websockify/noVNC ──► :6080      │
│                                                             │
│  /data/chrome ◄── persistent Linux Chrome identity          │
└─────────────────────────────────────────────────────────────┘
```

The human and agent do not control separate browsers. noVNC and CDP converge on the same Chrome process.

## Process ownership

| Process | Purpose |
| --- | --- |
| Xvfb | Virtual X display for headful Chrome |
| Openbox | Minimal window manager |
| Google Chrome | Actual browser/session |
| x11vnc | Reads the X framebuffer |
| websockify/noVNC | Exposes VNC to a normal web browser |
| socat | Relays container-reachable CDP to Chrome's loopback listener |
| supervisord | Keeps the process set alive |
| tini | Container PID 1 / signal handling |

## Why CDP uses a relay

Chrome listens on `127.0.0.1:${CHROME_INTERNAL_CDP_PORT}` inside the container. `socat` deliberately exposes `:${CDP_PORT}` to the container network.

That keeps Chrome's own debugging listener on loopback and lets deployment configuration decide whether CDP is reachable from siblings, localhost, or nowhere outside the container.

## Why the profile path is explicit

Chrome 136+ requires remote debugging to use a non-default user-data directory. The image uses:

```text
/data/chrome
```

That path is both the CDP-compatible user-data directory and the durable browser-identity boundary.

## Platform

The current image is intentionally `linux/amd64` because the installed Google Chrome package is amd64. The Dockerfile fails fast on other target architectures.

`compose.yaml` declares `BROWSER_PLATFORM=linux/amd64` by default so Apple-Silicon Docker Desktop selects emulation before entering the image build.
