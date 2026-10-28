#!/usr/bin/env bash
set -euo pipefail

for _ in $(seq 1 100); do
  if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if ! xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
  echo "ERROR: X display ${DISPLAY} did not become ready" >&2
  exit 1
fi

args=(
  "--user-data-dir=${CHROME_USER_DATA_DIR}"
  "--remote-debugging-address=127.0.0.1"
  "--remote-debugging-port=${CHROME_INTERNAL_CDP_PORT}"
  "--no-first-run"
  "--no-default-browser-check"
  "--password-store=basic"
  "--window-size=${SCREEN_WIDTH},${SCREEN_HEIGHT}"
  "--start-maximized"
)

if [[ "${CHROME_DISABLE_SANDBOX:-0}" == "1" ]]; then
  echo "WARNING: Chrome sandbox explicitly disabled by CHROME_DISABLE_SANDBOX=1" >&2
  args+=("--no-sandbox")
fi

if [[ -n "${CHROME_EXTRA_ARGS:-}" ]]; then
  read -r -a extra_args <<< "${CHROME_EXTRA_ARGS}"
  args+=("${extra_args[@]}")
fi

exec /usr/bin/google-chrome-stable "${args[@]}" "${CHROME_START_URL}"
