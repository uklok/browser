# Quick start

## Local development

```bash
cp .env.example .env

docker compose \
  -f compose.yaml \
  -f local.yaml \
  up --build -d
```

Open:

- noVNC: <http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale>
- CDP metadata: <http://127.0.0.1:9222/json/version>

Check health:

```bash
docker compose -f compose.yaml -f local.yaml ps
curl http://127.0.0.1:9222/json/version
```

## Local development with a host-visible profile

Use an **empty directory owned by this container browser**:

```bash
mkdir -p "$HOME/.uklok-browser/chrome-profile"

docker compose \
  -f compose.yaml \
  -f local.yaml \
  -f bind-profile.yaml \
  up --build -d
```

Log in once through noVNC. Then verify persistence:

```bash
docker compose \
  -f compose.yaml \
  -f local.yaml \
  -f bind-profile.yaml \
  down

docker compose \
  -f compose.yaml \
  -f local.yaml \
  -f bind-profile.yaml \
  up -d
```

Do not add `--volumes` if you want to preserve the named profile volume.

## Live operation-reading capture

The fixture suites build CDP events in process. This companion path sends the same pressure scenarios through the running shared Chrome session and then verifies the captured operation reading.

```bash
docker compose \
  -f compose.yaml \
  -f local.yaml \
  -f honeypot.yaml \
  up -d --no-deps --build reading-honeypot

BU_CDP_URL=http://127.0.0.1:${CDP_HOST_PORT:-9222} \
  ./bin/browser-automation run reading_honeypot --capture-traffic

python3 tests/reading-honeypot-live.py \
  .runs/reading_honeypot/<run-id>
```

The verifier is the check surface: it reads the honeypot checkpoint target ID, builds a temporary target-only view of the shared-browser capture, derives operations there, and asserts the reviewed expectations in `automations/reading_honeypot/expectations.json`. It never rewrites the raw capture. A normal run must prove the redirect, stable/opaque paths, GraphQL variants and batch result provenance, canonical host observations, bucket grouping, reconciliation, and absence of fixture secrets.

The deliberate fail-closed path is a separate run:

```bash
BU_CDP_URL=http://127.0.0.1:${CDP_HOST_PORT:-9222} \
  ./bin/browser-automation run reading_honeypot \
    --capture-traffic \
    --input fail_closed=true

python3 tests/reading-honeypot-live.py \
  .runs/reading_honeypot/<fail-closed-run-id>
```

That run is successful at the browser checkpoint but its **operation derivation must fail in staging** because the captured requests deliberately place synthetic lifted values in a GraphQL comment and a JSON field name. The verifier confirms those traps were actually captured and that no derived index, step operations, or `traffic/secrets.env` were published.

Chrome reaches `a.reading.test`, `b.reading.test`, `api.reading.test`, and `port.reading.test` only on the Compose network; the honeypot publishes no host port. Raw recorder evidence can still contain unrelated open-tab traffic and credentials, remains gitignored under `.runs/`, and should be deleted when the proof is no longer needed. Do not manually filter it for acceptance: use the target-isolating verifier above.

## Canonical container-network deployment

`compose.yaml` publishes no host ports:

```bash
docker compose up -d
```

Sibling containers can use:

```text
http://browser:9222
http://browser:6080
```

Set `BROWSER_IMAGE` to an immutable `sha-*` or full semantic-version tag for deployments that require reproducibility.

## Remote human access

Use the local overlay on the remote host and tunnel the loopback ports:

```bash
ssh -N \
  -L 6080:127.0.0.1:6080 \
  -L 9222:127.0.0.1:9222 \
  user@browser-host
```

Never expose CDP or noVNC directly to the public Internet.

## Next: agent control

With the local browser healthy:

```bash
./bin/browser-use-setup
./bin/browser-use-doctor
```

Then follow [Browser Use — Phase A](browser-use.md). Browser Use attaches to the existing CDP endpoint; the Chrome/profile/noVNC lifecycle stays owned by UKLOK Browser.

To prove the deterministic automation layer too:

```bash
./bin/browser-automation run example_read_page
```

See [Browser automations](automations.md) before creating site-specific workflows.
