#!/usr/bin/env bash
set -euo pipefail

exec Xvfb "${DISPLAY}" \
  -screen 0 "${SCREEN_WIDTH}x${SCREEN_HEIGHT}x${SCREEN_DEPTH}" \
  -nolisten tcp \
  -ac
