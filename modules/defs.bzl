"""Rules for building Envoy dynamic modules in the workbench.

The workbench's modules/ directory is injected into the envoy/ Bazel workspace
as @workbench (see scripts/bazel.sh), so modules build with Envoy's toolchain
and can depend on any repository Envoy has, e.g. "@boringssl//:ssl" or
"@googletest//:gtest_main".
"""

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_shared_library")

_SDK_ABI = "@envoy//source/extensions/dynamic_modules/sdk/cpp:sdk_abi"

def envoy_dynamic_module(name, srcs, deps = [], copts = [], visibility = ["//visibility:public"]):
    """Builds lib<name>.so, which Envoy loads as dynamic_module_config { name: <name> }.

    Everything in deps is linked statically into the .so. The
    envoy_dynamic_module_callback_* symbols stay undefined; the Envoy binary
    exports them and dlopen resolves them at load time.

    Args:
        name: Module name; the output is lib<name>.so.
        srcs: C++ sources that register the module's filters.
        deps: Extra cc_library dependencies.
        copts: Extra compiler options.
        visibility: Visibility of the shared library target.
    """
    lib = "_" + name + "_lib"
    cc_library(
        name = lib,
        srcs = srcs,
        copts = copts,
        deps = deps + [_SDK_ABI],
        # Filters register through static initializers that nothing references.
        alwayslink = True,
    )
    cc_shared_library(
        name = name,
        shared_lib_name = "lib{}.so".format(name),
        deps = [":" + lib],
        visibility = visibility,
    )
