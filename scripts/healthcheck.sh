#!/usr/bin/env bash
set -euo pipefail

pgrep -f '/usr/bin/google-chrome-stable|/opt/google/chrome/chrome' >/dev/null
curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${CDP_PORT}/json/version" >/dev/null
curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:${NOVNC_PORT}/vnc.html" >/dev/null
