# UKLOK Browser

A shared, **headful** Google Chrome session packaged as one Docker image.

A human can see and control the browser through noVNC while an agent or automation client controls the exact same Chrome session through the Chrome DevTools Protocol (CDP). The Chrome profile lives on a persistent volume so cookies, sessions, local storage, extensions, and preferences can survive container restarts.

## Architecture

```text
                         Docker host
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  browser container                                         │
│                                                            │
│  Xvfb :99 ──► Openbox ──► Google Chrome (headful)          │
│                              │                             │
│                              ├─ CDP 127.0.0.1:9223         │
│                              │        │                    │
│                              │      socat ──► :9222        │
│                              │                             │
│                              └─ framebuffer                │
│                                     │                      │
│                                  x11vnc                    │
│                              127.0.0.1:5900                │
│                                     │                      │
│                             websockify/noVNC ──► :6080     │
│                                                            │
│  /data/chrome ◄── persistent profile volume                │
└────────────────────────────────────────────────────────────┘
          ▲                                ▲
          │                                │
   127.0.0.1:6080                   127.0.0.1:9222
     human UI                         agent / CDP
```

The image deliberately keeps Chrome's own debugging listener on container loopback and relays it through `socat`. That avoids depending on Chrome's external bind behavior while letting the deployment decide whether the relay is reachable. The supplied Compose configuration publishes both human and agent surfaces to **host loopback only**.

## Why a custom profile is mandatory

Chrome 136+ ignores `--remote-debugging-port` for the default Chrome data directory. This image always launches Chrome with the explicit non-default profile path `/data/chrome`, which is also the persistence boundary.

Reference: <https://developer.chrome.com/blog/remote-debugging-port>

## Start

```bash
cp .env.example .env
docker compose up --build -d
```

Check health:

```bash
docker compose ps
curl http://127.0.0.1:9222/json/version
```

Open the human UI:

```text
http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale
```

The page displays the same Chrome instance exposed through CDP.

## Connect automation

Any client that can attach to an existing CDP browser can use:

```text
http://127.0.0.1:9222
```

Examples include Playwright's CDP connection and Chrome DevTools MCP clients that accept an existing browser URL.

Chrome itself listens on `127.0.0.1:9223` **inside** the container. The public-in-container `:9222` listener is only the relay.

## Remote access

Do **not** publish CDP or noVNC directly to the public Internet. Both surfaces can control a logged-in browser and therefore inherit the authority of its cookies and sessions.

The default Compose bindings are:

```text
127.0.0.1:6080 -> noVNC
127.0.0.1:9222 -> CDP
```

For a remote Docker host, tunnel them:

```bash
ssh -N \
  -L 6080:127.0.0.1:6080 \
  -L 9222:127.0.0.1:9222 \
  user@browser-host
```

Then use the same localhost URLs on your workstation. A private WireGuard/Tailscale network can replace the SSH tunnel, but the deployment should still treat both ports as privileged control surfaces.

### VNC password

`VNC_PASSWORD` is optional. When omitted, x11vnc accepts the local websockify connection without VNC authentication. That is intentional because **network isolation is the primary boundary** in the supplied deployment.

If you set `VNC_PASSWORD`, x11vnc enables legacy VNC password authentication. Do not treat that as a substitute for SSH/VPN/firewall isolation.

## Persistence

Compose creates the named volume `chrome-profile` and mounts it at:

```text
/data/chrome
```

Chrome receives the same path through `--user-data-dir`.

Remove the container without deleting the volume to preserve the browser identity:

```bash
docker compose down
docker compose up -d
```

Delete the profile intentionally:

```bash
docker compose down --volumes
```

That destroys saved browser state.

## Chrome sandbox

The image runs as the unprivileged `browser` user and does **not** disable Chrome's sandbox by default.

Some unusually restricted container runtimes prevent Chrome's sandbox from initializing. For diagnosis only, the image supports:

```bash
CHROME_DISABLE_SANDBOX=1 docker compose up
```

That adds `--no-sandbox` and weakens browser isolation. Prefer fixing the runtime rather than making this a permanent deployment setting.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCREEN_WIDTH` | `1440` | Virtual display width |
| `SCREEN_HEIGHT` | `900` | Virtual display height |
| `SCREEN_DEPTH` | `24` | Virtual display color depth |
| `NOVNC_HOST_PORT` | `6080` | Host-loopback port for noVNC |
| `CDP_HOST_PORT` | `9222` | Host-loopback port for CDP |
| `CHROME_START_URL` | `about:blank` | Initial page |
| `CHROME_EXTRA_ARGS` | empty | Additional whitespace-separated Chrome flags |
| `CHROME_DISABLE_SANDBOX` | `0` | Explicitly add `--no-sandbox` when set to `1` |
| `VNC_PASSWORD` | empty | Optional legacy VNC password |

Internal ports can also be changed when running the image directly: `NOVNC_PORT`, `VNC_PORT`, `CDP_PORT`, and `CHROME_INTERNAL_CDP_PORT`.

## Resource notes

Chrome is memory hungry. The supplied Compose file allocates a 2 GiB shared-memory segment because a tiny Docker `/dev/shm` is a common source of browser instability.

The first implementation targets `linux/amd64`, matching the Google Chrome APT repository declaration in the Dockerfile. Add an architecture only after its Chrome distribution path is verified and exercised in CI.

## Build and verify

Build:

```bash
docker build -t uklok/browser:local .
```

Run directly:

```bash
docker run -d \
  --name uklok-browser-smoke \
  --shm-size=2g \
  -p 127.0.0.1:6080:6080 \
  -p 127.0.0.1:9222:9222 \
  -v uklok-browser-profile:/data/chrome \
  uklok/browser:local
```

Wait for health and run the smoke contract:

```bash
docker inspect --format '{{.State.Health.Status}}' uklok-browser-smoke
./tests/smoke.sh uklok-browser-smoke
```

The smoke test verifies that:

- CDP reports Google Chrome;
- noVNC serves its client;
- the Chrome process is not launched with `--headless`;
- the persistent profile directory exists and is writable.

GitHub Actions performs this build-and-smoke sequence on branches and pull requests.

## Operational boundaries

- CDP is equivalent to browser control. Anyone who can reach it can navigate, execute JavaScript, read pages, and act with the browser's authenticated sessions.
- noVNC gives equivalent human keyboard/mouse control.
- Do not use a personal/default host Chrome profile as the container profile.
- Keep `/data/chrome` access scoped to the workload that owns this browser identity.
- Container isolation is not a substitute for account-level MFA, least privilege, or secret handling.

## Development governance

UKLOK's working contract lives at:

<https://github.com/uklok/ai-exchange/blob/main/AGENTS.md>

It is linked rather than copied here so this repository does not become a second owner of organization-wide working rules. Changes should flow through an issue, a feature branch, and a reviewable pull request.
