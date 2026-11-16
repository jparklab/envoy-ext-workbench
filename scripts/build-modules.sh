#!/usr/bin/env bash
# Build the dynamic modules in modules/ into build/modules/lib<name>.so.
# Usage: scripts/build-modules.sh [name ...]   (default: all modules)
# Set BUILD_TYPE=Debug for a debug build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/modules"

cmake -S "$REPO_ROOT/modules" -B "$BUILD_DIR" \
  -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE:-Release}" >/dev/null
targets=()
for name in "$@"; do targets+=(--target "$name"); done
cmake --build "$BUILD_DIR" -j "$(nproc)" "${targets[@]}"
echo "Built into: $BUILD_DIR"
