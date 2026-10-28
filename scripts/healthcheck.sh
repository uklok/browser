#!/usr/bin/env bash
set -euo pipefail

if ! pgrep -f '/usr/bin/google-chrome-stable|/opt/google/chrome/chrome' >/dev/null; then
  echo "UNHEALTHY: Chrome process is not running" >&2
  exit 1
fi

if ! curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${CDP_PORT}/json/version" >/dev/null; then
  echo "UNHEALTHY: Chrome DevTools endpoint is not responding on 127.0.0.1:${CDP_PORT}" >&2
  exit 1
fi

if ! curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${NOVNC_PORT}/vnc.html" >/dev/null; then
  echo "UNHEALTHY: noVNC web client is not responding on 127.0.0.1:${NOVNC_PORT}" >&2
  exit 1
fi
