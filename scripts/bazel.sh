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

# MIT Kerberos source for @workbench//third_party/mit_krb5, built from source
# and linked statically into modules. An injected repository can't declare
# downloads, so the pinned release is fetched here, checked against its
# sha256, and unpacked (its src/ directory) into the gitignored
# modules/third_party/mit_krb5/src. Bump the version and hash together; the
# release is signed by MIT (https://kerberos.org/dist/), verify before bumping.
KRB5_VERSION="1.22.3"
KRB5_SHA256="fe90af8441ad9fa9b064b8e53077cefb782a96f8a68276b031dc54af1789ff0b"
fetch_krb5_source() {
  local dst="$REPO_ROOT/modules/third_party/mit_krb5/src"
  local stamp="$dst/.workbench-release" want="krb5-$KRB5_VERSION $KRB5_SHA256"
  [[ -f "$stamp" && "$(cat "$stamp")" == "$want" ]] && return 0
  local dl="$REPO_ROOT/build/downloads" tarball="krb5-$KRB5_VERSION.tar.gz"
  local minor="${KRB5_VERSION%.*}"
  mkdir -p "$dl"
  if ! echo "$KRB5_SHA256  $dl/$tarball" | sha256sum -c --status 2>/dev/null; then
    echo "Fetching MIT Kerberos $KRB5_VERSION" >&2
    curl -fsSL -o "$dl/$tarball.part" "https://kerberos.org/dist/krb5/$minor/$tarball"
    echo "$KRB5_SHA256  $dl/$tarball.part" | sha256sum -c --status ||
      { echo "$0: $tarball: sha256 mismatch" >&2; rm -f "$dl/$tarball.part"; exit 1; }
    mv "$dl/$tarball.part" "$dl/$tarball"
  fi
  rm -rf "$dst"
  mkdir -p "$dst"
  tar -xzf "$dl/$tarball" -C "$dst" --strip-components=2 "krb5-$KRB5_VERSION/src"
  echo "$want" >"$stamp"
}
fetch_krb5_source
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
