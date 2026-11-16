#!/usr/bin/env bash
# Build the modules, then run every tests/*_test.sh against the built Envoy.
# Usage: scripts/test.sh [test-name ...]   e.g. scripts/test.sh add_header_test
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -x "$REPO_ROOT/envoy/bazel-bin/source/exe/envoy-static" ]]; then
  echo "Envoy binary not found; run scripts/build-envoy.sh first." >&2
  exit 1
fi
"$REPO_ROOT/scripts/build-modules.sh" >/dev/null

if [[ $# -gt 0 ]]; then
  tests=()
  for name in "$@"; do tests+=("$REPO_ROOT/tests/$name.sh"); done
else
  tests=("$REPO_ROOT"/tests/*_test.sh)
fi

failed=0
for t in "${tests[@]}"; do
  bash "$t" || failed=$((failed + 1))
done

echo "${#tests[@]} test(s), $failed failed"
[[ $failed -eq 0 ]]
