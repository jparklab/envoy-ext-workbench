#!/usr/bin/env bash
# Build the Envoy binary from the pinned submodule.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$REPO_ROOT/envoy"
bazel build -c opt //source/exe:envoy-static "$@"
echo "Built: $REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static"
