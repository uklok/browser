# Profiles & identity

The browser profile is an **identity**, not just a cache directory.

## Supported persistence models

### Named volume

Default `compose.yaml`:

```text
chrome-profile:/data/chrome
```

Best when the profile only needs to live with Docker.

### Host-backed Linux profile

`bind-profile.yaml`:

```text
$HOME/.uklok-browser/chrome-profile -> /data/chrome
```

Best when the container-owned profile needs host-level backup/inspection.

The directory still belongs exclusively to the Linux Chrome instance.

## Bootstrap authentication

For a new durable identity:

1. start an empty named/bind profile;
2. open Chrome through noVNC;
3. authenticate to the required sites once;
4. stop and recreate the container without deleting the profile;
5. verify the authenticated session survives.

This lifecycle has been observed successfully with Upwork after a full `down + up`.

## Do not share a host Chrome profile

Do **not** point `BROWSER_PROFILE_PATH` at a macOS or Windows Chrome user-data directory.

Why:

- profile files may contain portable history/tab metadata;
- authentication material depends on platform-specific secret storage;
- macOS Chrome uses Keychain-backed key material;
- Linux Chrome uses Linux-side secret storage/basic storage in this image;
- copying/binding the directory does not copy the host OS cryptographic context.

A copied cross-platform profile can therefore restore tabs while losing authenticated sessions.

## Managed-profile marker

For bind mounts, UKLOK Browser writes:

```text
.uklok-browser-managed
```

If the target is non-empty and lacks that marker, startup refuses to use it by default.

This is a guard against accidentally handing a host browser profile to Linux Chrome.

For a same-platform profile that you intentionally transfer permanently:

```bash
BROWSER_PROFILE_ADOPT_EXISTING=1 ...
```

Treat that as ownership transfer, never sharing.

## Stale ProcessSingleton locks

Chrome uses `SingletonLock`, `SingletonCookie`, and `SingletonSocket` to prevent concurrent use of one profile.

Those artifacts can persist across a recreated container and refer to a dead PID/hostname. For a UKLOK-managed profile, startup clears those stale singleton artifacts before launching Chrome.

This prevents the repeated “profile appears to be in use by another Google Chrome process” dialog after `down + up`.

## Destructive operations

```bash
docker compose down --volumes
```

deletes the named profile volume. Use it only when intentionally discarding browser identity.
