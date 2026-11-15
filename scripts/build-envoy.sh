#!/usr/bin/env bash
# Build the Envoy binary from the pinned submodule.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Prefer bazelisk: it honors envoy/.bazelversion. (Bazelisk builds from before
# MODULE.bazel support ignore .bazelversion and fetch the latest Bazel instead.)
BAZEL="$(command -v bazelisk || command -v bazel)"

cd "$REPO_ROOT/envoy"
"$BAZEL" build -c opt //source/exe:envoy-static "$@"
echo "Built: $REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static"
