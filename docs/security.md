# Security boundaries

## Treat both control surfaces as privileged

CDP and noVNC can operate an authenticated browser. Access to either can imply access to cookies, pages, account actions, and session authority.

The base deployment therefore publishes **no host ports**.

## Network rule

Preferred order:

1. Docker sibling network
2. host loopback
3. SSH / WireGuard / Tailscale tunnel

Do not bind CDP or noVNC directly to a public interface.

## Sandbox rule

Production/base behavior:

```text
CHROME_DISABLE_SANDBOX=0
CHROME_ALLOW_SANDBOX_FALLBACK=0
```

The local overlay can arm a narrow fallback because Docker Desktop under Apple-Silicon amd64 emulation has been observed to reject Chrome's namespace setup.

Local behavior:

1. start Chrome with sandbox;
2. if startup specifically reports `Failed to move to new namespace`;
3. retry with `--no-sandbox`.

Disable even that local fallback with:

```bash
LOCAL_CHROME_ALLOW_SANDBOX_FALLBACK=0 \
docker compose -f compose.yaml -f local.yaml up --build -d
```

Any `--no-sandbox` execution weakens Chrome isolation.

## VNC password

`VNC_PASSWORD` is optional. Legacy VNC password authentication is not the primary security boundary and must not replace network isolation.

## Profile boundary

A profile contains durable browser authority.

- keep `/data/chrome` scoped to the workload that owns it;
- never concurrently mount the same profile into two Chrome instances;
- never assume a macOS/Windows profile is authentication-portable to Linux;
- back up host-bound profiles before experimental migrations.
