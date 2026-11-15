#!/usr/bin/env bash
# Run the locally built Envoy with a config from configs/.
# Usage: scripts/run.sh [config]   (default: configs/envoy.yaml)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVOY_BIN="$REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static"
CONFIG="${1:-$REPO_ROOT/configs/envoy.yaml}"

if [[ ! -x "$ENVOY_BIN" ]]; then
  echo "Envoy binary not found at $ENVOY_BIN; run scripts/build-envoy.sh first." >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found: $CONFIG" >&2
  exit 1
fi

# Where Envoy looks for lib<name>.so dynamic modules; build-module.sh writes here.
export ENVOY_DYNAMIC_MODULES_SEARCH_PATH="${ENVOY_DYNAMIC_MODULES_SEARCH_PATH:-$REPO_ROOT/build/module}"

exec "$ENVOY_BIN" -c "$CONFIG" "${@:2}"
