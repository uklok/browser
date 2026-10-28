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

if [[ -n "${CHROME_EXTRA_ARGS:-}" ]]; then
  read -r -a extra_args <<< "${CHROME_EXTRA_ARGS}"
  args+=("${extra_args[@]}")
fi

if [[ "${CHROME_DISABLE_SANDBOX:-0}" == "1" ]]; then
  echo "WARNING: Chrome sandbox explicitly disabled by CHROME_DISABLE_SANDBOX=1" >&2
  exec /usr/bin/google-chrome-stable "${args[@]}" --no-sandbox "${CHROME_START_URL}"
fi

if [[ "${CHROME_ALLOW_SANDBOX_FALLBACK:-0}" != "1" ]]; then
  exec /usr/bin/google-chrome-stable "${args[@]}" "${CHROME_START_URL}"
fi

startup_log=/run/browser/chrome-startup.log
: > "${startup_log}"

echo "Chrome sandbox fallback is armed for this local runtime; trying sandboxed Chrome first." >&2

set +e
/usr/bin/google-chrome-stable "${args[@]}" "${CHROME_START_URL}" 2>&1 | tee "${startup_log}"
chrome_status=${PIPESTATUS[0]}
set -e

if [[ "${chrome_status}" -ne 0 ]] && grep -q "Failed to move to new namespace" "${startup_log}"; then
  echo "WARNING: Chrome sandbox namespace setup is unsupported by this runtime; retrying with --no-sandbox." >&2
  echo "WARNING: This fallback weakens browser isolation and is intended only for the explicit local-development overlay." >&2
  exec /usr/bin/google-chrome-stable "${args[@]}" --no-sandbox "${CHROME_START_URL}"
fi

exit "${chrome_status}"
