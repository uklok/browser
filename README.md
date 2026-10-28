# UKLOK Browser

One **headful Google Chrome** session that a human and an agent can share.

- Human control: noVNC
- Agent control: Chrome DevTools Protocol (CDP)
- Durable identity: persistent Linux Chrome profile
- Default deployment: Docker-network only
- Local development: loopback-only host access
- Current image platform: `linux/amd64`

## Choose your path

| I want to… | Go here |
| --- | --- |
| Run it locally | [Quick start](docs/quickstart.md) |
| Understand the moving parts | [Architecture](docs/architecture.md) |
| Keep logins across restarts | [Profiles & identity](docs/profiles.md) |
| Debug a black screen / unhealthy browser | [Operations](docs/operations.md) |
| Understand the security boundaries | [Security](docs/security.md) |
| Publish or pin an image version | [Releases](docs/releases.md) |
| Work on this repo as an agent | [AGENTS.md](AGENTS.md) |

Full documentation index: [docs/README.md](docs/README.md).

## Fastest local start

```bash
cp .env.example .env

docker compose \
  -f compose.yaml \
  -f local.yaml \
  up --build -d
```

Then:

- noVNC: <http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale>
- CDP: <http://127.0.0.1:9222/json/version>

On Apple Silicon, Docker Desktop runs the current `linux/amd64` image through emulation. The local overlay attempts sandboxed Chrome first and only falls back to `--no-sandbox` for the known namespace failure. Production does not enable that fallback.

## Persistent browser identity

The easiest persistence path is the named Docker volume in `compose.yaml`.

For a host-visible profile owned by the Linux container:

```bash
mkdir -p "$HOME/.uklok-browser/chrome-profile"

docker compose \
  -f compose.yaml \
  -f local.yaml \
  -f bind-profile.yaml \
  up --build -d
```

Authenticate once **inside this Linux Chrome session**. Do not mount a macOS/Windows Chrome user-data directory into the container; authentication secrets are not cross-platform portable. See [Profiles & identity](docs/profiles.md).

## Runtime contract

A healthy session means all of these are true:

1. Xvfb is alive.
2. Chrome is headful and running.
3. CDP answers on `:9222`.
4. noVNC serves the same display on `:6080`.
5. The Chrome profile is writable and survives restart.

`tests/smoke.sh` encodes that contract.

## Governance

Organization working rules are anchored by the UKLOK agent entrypoint:

<https://github.com/uklok/ai-exchange/blob/main/AGENTS.md>

Repository-specific agent guidance lives in [AGENTS.md](AGENTS.md).
