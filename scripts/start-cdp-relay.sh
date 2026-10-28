#!/usr/bin/env bash
set -euo pipefail

exec /usr/bin/socat \
  "TCP-LISTEN:${CDP_PORT},bind=0.0.0.0,reuseaddr,fork" \
  "TCP:127.0.0.1:${CHROME_INTERNAL_CDP_PORT}"
