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

# MIT Kerberos headers for @workbench//third_party/mit_krb5:headers: symlinks
# to the host's (libkrb5-dev), only the Kerberos ones, so the hermetic
# sysroot's libc headers are never shadowed.
link_krb5_headers() {
  local dst="$REPO_ROOT/modules/third_party/mit_krb5/include" inc="/usr/include" flag et h
  if command -v krb5-config >/dev/null; then
    for flag in $(krb5-config --cflags krb5 gssapi); do
      [[ "$flag" == -I?* ]] && inc="${flag#-I}"
      [[ "$flag" == /* ]] && inc="$flag" # After -isystem.
    done
  fi
  [[ -f "$inc/krb5.h" ]] || return 0 # No libkrb5-dev: Kerberos code won't build.
  mkdir -p "$dst"
  for h in krb5.h krb5 gssapi.h gssapi profile.h; do
    [[ -e "$inc/$h" ]] && ln -sfn "$inc/$h" "$dst/$h"
  done
  for et in "$inc/et" /usr/include/et; do
    [[ -d "$et" ]] && { ln -sfn "$et" "$dst/et"; break; }
  done
  return 0
}
link_krb5_headers
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
