# Releases

The package owner is:

```text
ghcr.io/uklok/browser
```

## What triggers validation

PR CI runs only when browser/runtime, Compose, tests, environment contract, or workflow inputs change.

Documentation-only changes do not rebuild the image.

## What triggers publication

The publish workflow runs when image-producing inputs reach `main`:

```text
Dockerfile
.dockerignore
scripts/**
supervisord.conf
```

An explicit `vX.Y.Z` tag is also a release signal.

## Tag meanings

| Tag | Meaning |
| --- | --- |
| `edge` | Latest accepted image-producing build on `main` |
| `sha-*` | Commit-derived immutable deployment reference |
| `X.Y.Z` | Full semantic release |
| `X.Y` | Latest patch in a minor line |
| `X` | Latest release in a major line |
| `latest` | Latest explicit semantic release |

Prefer a full semver or `sha-*` tag for reproducible deployments.

## Publication proof

Before pushing a package, the workflow:

1. builds `linux/amd64`;
2. starts Chrome;
3. waits for container health;
4. runs the smoke contract;
5. restarts with the same profile;
6. runs the smoke contract again;
7. logs into GHCR;
8. publishes the versioned image.

The package carries OCI source metadata linking it back to this repository.
