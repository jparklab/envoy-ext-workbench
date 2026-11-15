#!/usr/bin/env bash
# Build the dynamic module in module/ into build/module/libworkbench.so.
# Extra args go to the CMake configure step, e.g. -DCMAKE_BUILD_TYPE=Debug.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/module"

cmake -S "$REPO_ROOT/module" -B "$BUILD_DIR" \
  -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
  -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build "$BUILD_DIR" -j "$(nproc)"
echo "Built: $BUILD_DIR/libworkbench.so"
