# UKLOK Browser

A shared, **headful** Google Chrome session packaged as one Docker image.

A human can see and control the browser through noVNC while an agent or automation client controls the exact same Chrome session through the Chrome DevTools Protocol (CDP). The Chrome profile lives at `/data/chrome` and can be backed by either a Docker volume or an explicit host bind.

## Architecture

```text
                         Docker network
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
│  /data/chrome ◄── persistent profile                       │
└────────────────────────────────────────────────────────────┘
          ▲                                ▲
          │                                │
   browser:6080                     browser:9222
   sibling human UI                 sibling agent / CDP
```

Chrome's own debugging listener remains on container loopback and is deliberately relayed through `socat`. The base Compose model publishes **no host ports**: only sibling containers on the Compose network can reach `browser:6080` and `browser:9222`.

## Published image and versioning

The pipeline publishes this repository as:

```text
ghcr.io/uklok/browser
```

Tags have distinct stability semantics:

- every accepted `main` build publishes `edge` plus an immutable commit-derived `sha-<short-sha>` tag;
- pushing a semantic version tag such as `v1.2.3` publishes `1.2.3`, `1.2`, `1`, `latest`, and the corresponding `sha-*` tag;
- production deployments should pin a full semantic version or `sha-*` tag rather than following `edge`.

The package is linked back to this repository through OCI source metadata. GitHub Container Registry packages are private when first created unless organization/package visibility is changed explicitly, so authenticate with `docker login ghcr.io` when required.

## Why a custom profile is mandatory

Chrome 136+ ignores `--remote-debugging-port` for the default Chrome data directory. This image always launches Chrome with the explicit non-default profile path `/data/chrome`, which is also the persistence boundary.

Reference: <https://developer.chrome.com/blog/remote-debugging-port>

## Deployment: container-network only

The canonical deployment consumes the published package and exposes no ports to the Docker host:

```bash
cp .env.example .env
docker compose up -d
```

A sibling service in the same Compose project can connect to:

```text
http://browser:9222   # CDP
http://browser:6080   # noVNC
```

Set `BROWSER_IMAGE` to the exact package tag the deployment should trust, for example:

```bash
BROWSER_IMAGE=ghcr.io/uklok/browser:1.2.3 docker compose up -d
```

## Local development and human access

`local.yaml` is the development overlay. It builds the current checkout and publishes CDP/noVNC to **host loopback only**:

```bash
docker compose -f compose.yaml -f local.yaml up --build -d
```

Then:

```bash
curl http://127.0.0.1:9222/json/version
```

and open:

```text
http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale
```

For a remote Docker host, keep the loopback bindings and tunnel them:

```bash
ssh -N \
  -L 6080:127.0.0.1:6080 \
  -L 9222:127.0.0.1:9222 \
  user@browser-host
```

Do **not** publish CDP or noVNC directly to the public Internet. Both surfaces can control a logged-in browser and therefore inherit the authority of its cookies and sessions.

### VNC password

`VNC_PASSWORD` is optional. When omitted, x11vnc accepts the local websockify connection without VNC authentication. Network isolation is the primary boundary.

If you set `VNC_PASSWORD`, x11vnc enables legacy VNC password authentication. Do not treat that as a substitute for SSH/VPN/firewall isolation.

## Persistence

By default, `compose.yaml` uses the named volume `chrome-profile` at:

```text
/data/chrome
```

Remove/recreate the container without deleting that volume to preserve browser identity:

```bash
docker compose down
docker compose up -d
```

Delete the named profile intentionally:

```bash
docker compose down --volumes
```

### Bind or migrate a host profile

`bind-profile.yaml` replaces the named volume at the same container target with a host bind. Docker Compose merges volumes by container target, so the later overlay replaces `chrome-profile:/data/chrome`.

The default host path is:

```text
$HOME/.chrome-upwork-cdp
```

Create it first and make sure it is writable by the image's browser user (UID 1000):

```bash
mkdir -p "${BROWSER_PROFILE_PATH:-$HOME/.chrome-upwork-cdp}"
```

Use the bind with the published image:

```bash
docker compose \
  -f compose.yaml \
  -f bind-profile.yaml \
  up -d
```

Or combine it with the local-development overlay:

```bash
docker compose \
  -f compose.yaml \
  -f local.yaml \
  -f bind-profile.yaml \
  up --build -d
```

Override the source when needed:

```bash
BROWSER_PROFILE_PATH=/path/to/dedicated/chrome-profile \
docker compose -f compose.yaml -f bind-profile.yaml up -d
```

For migration, copy an existing Chrome profile into a **dedicated, inactive** directory and bind that copy. Do not mount the same live profile into host Chrome and container Chrome simultaneously; Chrome profile locks and concurrent writes make that unsafe.

## Chrome sandbox

The image runs as the unprivileged `browser` user and does **not** disable Chrome's sandbox by default.

Some unusually restricted container runtimes prevent Chrome's sandbox from initializing. For diagnosis only:

```bash
CHROME_DISABLE_SANDBOX=1 docker compose -f compose.yaml -f local.yaml up --build
```

That adds `--no-sandbox` and weakens browser isolation. Prefer fixing the runtime rather than making this permanent.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BROWSER_IMAGE` | `ghcr.io/uklok/browser:edge` | Published package reference used by the base deployment |
| `BROWSER_PROFILE_PATH` | `$HOME/.chrome-upwork-cdp` | Host profile path used by `bind-profile.yaml` |
| `SCREEN_WIDTH` | `1440` | Virtual display width |
| `SCREEN_HEIGHT` | `900` | Virtual display height |
| `SCREEN_DEPTH` | `24` | Virtual display color depth |
| `NOVNC_HOST_PORT` | `6080` | Host-loopback noVNC port in `local.yaml` |
| `CDP_HOST_PORT` | `9222` | Host-loopback CDP port in `local.yaml` |
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
- Xvfb is alive;
- the Chrome process is not launched with `--headless`;
- the persistent profile directory exists and is writable.

GitHub Actions performs build-and-smoke validation on pull requests and accepted pushes. Package publication happens only after that validation succeeds on `main` or a semantic version tag.

## Operational boundaries

- CDP is equivalent to browser control. Anyone who can reach it can navigate, execute JavaScript, read pages, and act with the browser's authenticated sessions.
- noVNC gives equivalent human keyboard/mouse control.
- Keep `/data/chrome` access scoped to the workload that owns this browser identity.
- Prefer a dedicated copied profile for bind mounts rather than the default host Chrome profile.
- Container isolation is not a substitute for account-level MFA, least privilege, or secret handling.

## Development governance

UKLOK's working contract lives at:

<https://github.com/uklok/ai-exchange/blob/main/AGENTS.md>

It is linked rather than copied here so this repository does not become a second owner of organization-wide working rules. Changes should flow through an issue, a feature branch, and a reviewable pull request.
