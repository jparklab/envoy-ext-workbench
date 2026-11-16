#!/usr/bin/env bash
# Build the dynamic modules in modules/ with Bazel (see scripts/bazel.sh) and
# copy each lib<name>.so to build/modules/, where run.sh points Envoy.
# Usage: scripts/build-modules.sh [name ...]   (default: all modules)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/build/modules"
BAZEL_SH="$REPO_ROOT/scripts/bazel.sh"

if [[ $# -gt 0 ]]; then
  targets=()
  for name in "$@"; do targets+=("@workbench//$name"); done
else
  targets=("@workbench//...")
fi

"$BAZEL_SH" build "${targets[@]}"

expr="$(printf ' + %s' "${targets[@]}")"
libs="$("$BAZEL_SH" cquery "kind(cc_shared_library, ${expr# + })" --output=files 2>/dev/null)"
[[ -n "$libs" ]] || { echo "No modules found for: ${targets[*]}" >&2; exit 1; }

mkdir -p "$OUT_DIR"
while read -r lib; do
  install -m 0755 "$REPO_ROOT/envoy/$lib" "$OUT_DIR/"
  echo "Built: $OUT_DIR/$(basename "$lib")"
done <<<"$libs"
