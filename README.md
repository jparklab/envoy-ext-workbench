# envoy-ext-workbench

Envoy dynamic module extensions, with configs, scripts and a pinned Envoy
submodule for building and testing.

## Layout

```
envoy/      git submodule, pinned to Envoy v1.40.2
modules/    dynamic modules (C++ SDK, CMake), one directory per module
configs/    Envoy configs: envoy.yaml (plain), <module>.yaml (loads that module)
scripts/    build-envoy.sh, build-modules.sh, run.sh, test.sh
tests/      *_test.sh integration tests against the built Envoy
```

## Getting started

Prerequisites (Ubuntu): a current bazelisk, plus
`sudo apt-get install autoconf curl libxml2-dev libtool patch python3-pip unzip virtualenv cmake clang`.
Bazel downloads Envoy's own Clang toolchain. Bazelisk builds from before
MODULE.bazel support ignore `envoy/.bazelversion`; install a current one with
`go install github.com/bazelbuild/bazelisk@latest`.

```sh
git clone --recurse-submodules --shallow-submodules git@github.com:jparklab/envoy-ext-workbench.git
cd envoy-ext-workbench
scripts/build-envoy.sh                 # long first build
scripts/run.sh                         # serves "ok" on :10000, admin on 127.0.0.1:9901
curl localhost:10000
```

## Dynamic modules

Each directory under `modules/` is one module, built into
`build/modules/lib<name>.so` and loaded by Envoy as
`dynamic_module_config: { name: <name> }`. Modules use the C++ SDK from
`envoy/source/extensions/dynamic_modules/sdk/cpp`, compiled once from the
submodule with CMake and the system clang (C++20).

The starter module `add_header` sets an `x-workbench` response header to its
`filter_config` string.

```sh
scripts/build-modules.sh                  # all modules; or: scripts/build-modules.sh add_header
scripts/run.sh configs/add_header.yaml    # sets ENVOY_DYNAMIC_MODULES_SEARCH_PATH=build/modules
curl -i localhost:10000                   # x-workbench: from-workbench
scripts/test.sh                           # builds modules, runs tests/*_test.sh
```

To add a module `foo`: create `modules/foo/foo.cc` and
`modules/foo/CMakeLists.txt` containing `envoy_dynamic_module(foo foo.cc)`,
then add `configs/foo.yaml` and `tests/foo_test.sh`.

Envoy checks a hash of the module ABI header at load time, so build the module
from the same submodule commit as the Envoy binary.

## Upgrading Envoy

```sh
cd envoy
git fetch --depth 1 origin tag <tag>
git checkout <tag>
cd ..
git add envoy
git commit -m "Bump Envoy to <tag>"
```
