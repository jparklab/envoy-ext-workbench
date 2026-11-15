#!/usr/bin/env bash
# Starts Envoy with configs/module.yaml and checks that the workbench module's
# add_header filter sets x-workbench on the response.
# Needs: scripts/build-envoy.sh and scripts/build-module.sh already run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$(mktemp)"

"$REPO_ROOT/scripts/run.sh" "$REPO_ROOT/configs/module.yaml" --log-path "$LOG" &
ENVOY_PID=$!
trap 'kill "$ENVOY_PID" 2>/dev/null || true; wait "$ENVOY_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT

# Wait up to 10s for the admin endpoint to report LIVE.
for _ in $(seq 50); do
  if curl -sf http://127.0.0.1:9901/ready >/dev/null 2>&1; then break; fi
  if ! kill -0 "$ENVOY_PID" 2>/dev/null; then
    echo "FAIL: Envoy exited during startup" >&2; cat "$LOG" >&2; exit 1
  fi
  sleep 0.2
done

headers="$(curl -s -D - -o /dev/null http://127.0.0.1:10000/)"
if grep -qi '^x-workbench: from-workbench' <<<"$headers"; then
  echo "PASS: module_test"
else
  echo "FAIL: module_test: x-workbench header missing. Response headers:" >&2
  echo "$headers" >&2
  cat "$LOG" >&2
  exit 1
fi
