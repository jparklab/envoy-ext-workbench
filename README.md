# envoy-ext-workbench

Envoy dynamic module extensions, with configs, scripts and a pinned Envoy
submodule for building and testing.

## Layout

```
envoy/      git submodule, pinned to Envoy v1.40.2
module/     dynamic module source
configs/    Envoy configs
scripts/    build and run scripts
tests/      integration tests against the built Envoy
```

## Getting started

```sh
git clone --recurse-submodules --shallow-submodules git@github.com:jparklab/envoy-ext-workbench.git
cd envoy-ext-workbench
scripts/build-envoy.sh   # needs bazel (bazelisk recommended)
scripts/run.sh           # serves "ok" on :10000, admin on 127.0.0.1:9901
curl localhost:10000
```

Dynamic module SDKs (Rust, Go, C++) live in
`envoy/source/extensions/dynamic_modules/sdk/`. The module ABI changes between
Envoy releases, so build the module against the same Envoy version as the
binary.

## Upgrading Envoy

```sh
cd envoy
git fetch --depth 1 origin tag <tag>
git checkout <tag>
cd ..
git add envoy
git commit -m "Bump Envoy to <tag>"
```
