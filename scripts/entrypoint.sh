#!/usr/bin/env bash
set -euo pipefail

umask 077

mkdir -p "${CHROME_USER_DATA_DIR}" /run/browser

if [[ ! -w "${CHROME_USER_DATA_DIR}" ]]; then
  echo "ERROR: Chrome profile directory is not writable: ${CHROME_USER_DATA_DIR}" >&2
  exit 1
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

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/browser.conf
