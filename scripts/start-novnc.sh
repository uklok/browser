#!/usr/bin/env bash
set -euo pipefail

exec /usr/bin/websockify \
  --web=/usr/share/novnc \
  "0.0.0.0:${NOVNC_PORT}" \
  "127.0.0.1:${VNC_PORT}"
