load("@rules_cc//cc:defs.bzl", "cc_library")

# MIT Kerberos headers from the build host (libkrb5-dev), for code that loads
# libkrb5 at run time with dlopen rather than linking it: the hermetic
# toolchain's sysroot has an older glibc than the host's libkrb5 needs, and a
# module that links libkrb5 couldn't load on hosts without it. include/ holds
# symlinks to the host's headers, made by scripts/bazel.sh from krb5-config.
cc_library(
    name = "headers",
    hdrs = glob(["include/**/*.h"]),
    includes = ["include"],
    visibility = ["//visibility:public"],
)
