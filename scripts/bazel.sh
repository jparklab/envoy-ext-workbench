#!/usr/bin/env bash
# Run Bazel in the envoy/ submodule workspace with the workbench's modules/
# directory injected as the external repository @workbench.
# Usage: scripts/bazel.sh <command> [args ...]   e.g. scripts/bazel.sh test @workbench//...
#
# Modules build with Envoy's own toolchain, flags and dependencies (e.g.
# @boringssl, @googletest), and against the same abi.h as the Envoy binary.
# Every script goes through here so all invocations share one set of options;
# changing options between runs would discard Bazel's analysis cache.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Prefer bazelisk: it honors envoy/.bazelversion. (Bazelisk builds from before
# MODULE.bazel support ignore .bazelversion and fetch the latest Bazel instead.)
BAZEL="$(command -v bazelisk || command -v bazel)"

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args ...]" >&2
  exit 2
fi
cmd="$1"
shift
inject="--inject_repository=workbench=$REPO_ROOT/modules"

cd "$REPO_ROOT/envoy"
case "$cmd" in
  build | test | run | cquery | aquery | coverage)
    exec "$BAZEL" "$cmd" -c opt "$inject" "$@" ;;
  query)
    exec "$BAZEL" "$cmd" "$inject" "$@" ;;
  *)
    exec "$BAZEL" "$cmd" "$@" ;;
esac
