load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//:defs.bzl", "envoy_dynamic_module")

# TDS framing and connection tracking; no Envoy dependency, so unit-testable.
cc_library(
    name = "tds",
    srcs = [
        "tds.cc",
        "tds_connection.cc",
    ],
    hdrs = [
        "tds.h",
        "tds_connection.h",
    ],
)

envoy_dynamic_module(
    name = "mssql_proxy",
    srcs = ["mssql_proxy.cc"],
    deps = [":tds"],
)

# Recorded from a real SQL Server by testdata/record.sh.
filegroup(
    name = "fixtures",
    srcs = glob(["testdata/*.tds"]),
)

cc_test(
    name = "tds_test",
    srcs = ["tds_test.cc"],
    data = [":fixtures"],
    env = {"FIXTURES": "$(rlocationpaths :fixtures)"},
    deps = [
        ":tds",
        "@googletest//:gtest_main",
    ],
)
