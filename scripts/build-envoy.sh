#!/usr/bin/env bash
# Build the Envoy binary from the pinned submodule.
# Goes through scripts/bazel.sh so it shares Bazel options (and the analysis
# cache) with the module builds.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

"$REPO_ROOT/scripts/bazel.sh" build //source/exe:envoy-static "$@"
echo "Built: $REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static"
