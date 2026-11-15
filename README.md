# envoy-ext-workbench

Envoy dynamic module extensions, with configs, scripts and a pinned Envoy
submodule for building and testing.

## Layout

```
envoy/      git submodule, pinned to Envoy v1.40.2
module/     dynamic module source (C++ SDK, CMake), builds build/module/libworkbench.so
configs/    Envoy configs: envoy.yaml (plain), module.yaml (loads the module)
scripts/    build-envoy.sh, build-module.sh, run.sh, test.sh
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

## Dynamic module

`module/` uses the C++ SDK from `envoy/source/extensions/dynamic_modules/sdk/cpp`,
compiled straight from the submodule with CMake and the system clang (C++20).
The starter filter `add_header` sets an `x-workbench` response header to its
`filter_config` string.

```sh
scripts/build-module.sh                # -> build/module/libworkbench.so
scripts/run.sh configs/module.yaml     # sets ENVOY_DYNAMIC_MODULES_SEARCH_PATH=build/module
curl -i localhost:10000                # x-workbench: from-workbench
scripts/test.sh                        # builds the module, runs tests/*_test.sh
```

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
