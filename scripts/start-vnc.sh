#!/usr/bin/env bash
set -euo pipefail

for _ in $(seq 1 100); do
  if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

args=(
  "-display" "${DISPLAY}"
  "-rfbport" "${VNC_PORT}"
  "-listen" "127.0.0.1"
  "-forever"
  "-shared"
  "-xkb"
)

if [[ -n "${VNC_PASSWORD:-}" ]]; then
  args+=("-passwd" "${VNC_PASSWORD}")
else
  args+=("-nopw")
fi

exec /usr/bin/x11vnc "${args[@]}"
