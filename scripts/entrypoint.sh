#!/usr/bin/env bash
set -euo pipefail

umask 077

mkdir -p "${CHROME_USER_DATA_DIR}" /run/browser

if [[ ! -w "${CHROME_USER_DATA_DIR}" ]]; then
  echo "ERROR: Chrome profile directory is not writable: ${CHROME_USER_DATA_DIR}" >&2
  exit 1
fi

profile_marker="${CHROME_USER_DATA_DIR}/.uklok-browser-managed"
shopt -s dotglob nullglob
profile_entries=("${CHROME_USER_DATA_DIR}"/*)
shopt -u dotglob nullglob

if [[ ! -f "${profile_marker}" ]]; then
  if [[ "${#profile_entries[@]}" -gt 0 && "${CHROME_REQUIRE_PROFILE_MARKER:-0}" == "1" && "${CHROME_ADOPT_EXISTING_PROFILE:-0}" != "1" ]]; then
    echo "ERROR: Refusing to use a non-empty, unmanaged Chrome profile at ${CHROME_USER_DATA_DIR}." >&2
    echo "ERROR: Bind-mounted profiles must be dedicated to UKLOK Browser." >&2
    echo "ERROR: Do not bind a macOS/Windows Chrome user-data-dir into this Linux container." >&2
    echo "ERROR: Use an empty directory, or set CHROME_ADOPT_EXISTING_PROFILE=1 only for a profile you intentionally hand over exclusively to this Linux browser." >&2
    exit 1
  fi

  if [[ "${#profile_entries[@]}" -gt 0 ]]; then
    echo "WARNING: Adopting an existing profile directory for exclusive Linux-container ownership." >&2
  fi

  printf 'managed-by=uklok/browser\nplatform=linux\n' > "${profile_marker}"
fi

if [[ "${CHROME_CLEAR_STALE_SINGLETONS:-1}" == "1" ]]; then
  cleared=0
  for singleton in SingletonLock SingletonCookie SingletonSocket; do
    path="${CHROME_USER_DATA_DIR}/${singleton}"
    if [[ -e "${path}" || -L "${path}" ]]; then
      rm -f -- "${path}"
      cleared=1
    fi
  done
  if [[ "${cleared}" == "1" ]]; then
    echo "Cleared stale Chrome ProcessSingleton artifacts from the managed profile."
  fi
fi

if [[ -n "${VNC_PASSWORD:-}" ]]; then
  printf '%s\n' "${VNC_PASSWORD}" > /run/browser/vnc.pass
  chmod 0600 /run/browser/vnc.pass
else
  rm -f /run/browser/vnc.pass
  echo "WARNING: VNC authentication is disabled. Keep port ${NOVNC_PORT} bound to host loopback or a private network." >&2
fi

echo "Starting shared browser session"
echo "  display: ${DISPLAY} (${SCREEN_WIDTH}x${SCREEN_HEIGHT}x${SCREEN_DEPTH})"
echo "  profile: ${CHROME_USER_DATA_DIR}"
echo "  noVNC:   :${NOVNC_PORT}"
echo "  CDP:     :${CDP_PORT} -> 127.0.0.1:${CHROME_INTERNAL_CDP_PORT}"
if [[ "${CHROME_DISABLE_SANDBOX:-0}" == "1" ]]; then
  echo "  sandbox: disabled explicitly"
elif [[ "${CHROME_ALLOW_SANDBOX_FALLBACK:-0}" == "1" ]]; then
  echo "  sandbox: enabled, local namespace-failure fallback armed"
else
  echo "  sandbox: enabled, no fallback"
fi

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/browser.conf
