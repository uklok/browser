#!/usr/bin/env bash
set -euo pipefail

container="${1:-uklok-browser-smoke}"
cdp_url="${CDP_URL:-http://127.0.0.1:9222}"
novnc_url="${NOVNC_URL:-http://127.0.0.1:6080}"

version_json="$(curl --fail --silent --show-error "${cdp_url}/json/version")"

if ! jq -e '.Browser | startswith("Chrome/")' <<<"${version_json}" >/dev/null; then
  echo "CDP did not report Google Chrome" >&2
  echo "${version_json}" >&2
  exit 1
fi

curl --fail --silent --show-error "${novnc_url}/vnc.html" | grep -q '<title>noVNC'

chrome_processes="$(docker exec "${container}" sh -c 'ps auxww | grep -E "[g]oogle-chrome-stable|[/]opt/google/chrome/chrome"')"
if grep -q -- '--headless' <<<"${chrome_processes}"; then
  echo "Chrome unexpectedly started in headless mode" >&2
  echo "${chrome_processes}" >&2
  exit 1
fi

docker exec "${container}" pgrep -x Xvfb >/dev/null
docker exec "${container}" sh -c 'test -d "$CHROME_USER_DATA_DIR" && test -w "$CHROME_USER_DATA_DIR"'

echo "Smoke test passed: headful Chrome, Xvfb, CDP, noVNC, and writable persistent profile are present."
