load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//:defs.bzl", "envoy_dynamic_module")

# TDS framing, PRELOGIN/LOGIN7 parsing and connection tracking; no Envoy
# dependency, so unit-testable.
cc_library(
    name = "tds",
    srcs = [
        "login7.cc",
        "tds.cc",
        "tds_connection.cc",
    ],
    hdrs = [
        "login7.h",
        "tds.h",
        "tds_connection.h",
    ],
)

# Login following and policy: authentication token classification, login
# method, identity and result; no Envoy dependency.
cc_library(
    name = "auth",
    srcs = [
        "auth.cc",
        "der.cc",
        "gss_token.cc",
        "krb5_messages.cc",
        "ntlm.cc",
    ],
    hdrs = [
        "auth.h",
        "der.h",
        "gss_token.h",
        "krb5_messages.h",
        "ntlm.h",
    ],
    deps = [":tds"],
)

# Kerberos read_ticket and terminate with MIT Kerberos, linked statically.
cc_library(
    name = "kerberos",
    srcs = [
        "kerberos.cc",
        "kerberos_terminate.cc",
        "krb5_util.cc",
    ],
    hdrs = [
        "kerberos.h",
        "kerberos_terminate.h",
        "krb5_util.h",
    ],
    # Kerberos symbols are hidden, so whatever calls them must be in the same
    # link unit: never a shared library of its own (as tests would make it).
    linkstatic = True,
    deps = [
        ":auth",
        "//third_party/mit_krb5",
    ],
)

# TLS termination on both legs of a TDS 7.x connection; no Envoy dependency.
cc_library(
    name = "tls_bridge",
    srcs = ["tls_bridge.cc"],
    hdrs = ["tls_bridge.h"],
    deps = [
        ":auth",
        ":tds",
        "@boringssl//:ssl",
    ],
)

# Threads for work that may block (Kerberos steps); no Envoy dependency.
cc_library(
    name = "worker_pool",
    hdrs = ["worker_pool.h"],
)

# filter_config parsing; no Envoy dependency.
cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":tls_bridge",
        "@nlohmann_json//:json",
    ],
)

envoy_dynamic_module(
    name = "mssql_proxy",
    srcs = ["mssql_proxy.cc"],
    deps = [
        ":auth",
        ":config",
        ":kerberos",
        ":tds",
        ":tls_bridge",
        ":worker_pool",
    ],
)

# Recorded from a real SQL Server by testdata/record.sh.
filegroup(
    name = "fixtures",
    srcs = glob(["testdata/*.tds"]),
)

cc_library(
    name = "test_util",
    testonly = True,
    hdrs = ["test_util.h"],
    deps = [":tds"],
)

cc_test(
    name = "tds_test",
    srcs = ["tds_test.cc"],
    data = [":fixtures"],
    env = {"FIXTURES": "$(rlocationpaths :fixtures)"},
    deps = [
        ":tds",
        ":test_util",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "bridge_test_util",
    testonly = True,
    hdrs = ["bridge_test_util.h"],
    deps = [
        ":test_util",
        ":tls_bridge",
        "@googletest//:gtest",
    ],
)

cc_test(
    name = "tls_bridge_test",
    srcs = ["tls_bridge_test.cc"],
    deps = [
        ":bridge_test_util",
        ":test_util",
        ":tls_bridge",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "auth_test",
    srcs = ["auth_test.cc"],
    deps = [
        ":auth",
        ":test_util",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "kdc_test_util",
    testonly = True,
    hdrs = ["kdc_test_util.h"],
    deps = ["@googletest//:gtest"],
)

# Against a throwaway MIT KDC (testdata/mit_kdc.sh); skips without one.
cc_test(
    name = "kerberos_test",
    srcs = ["kerberos_test.cc"],
    data = ["testdata/mit_kdc.sh"],
    env = {"MIT_KDC": "$(rlocationpath testdata/mit_kdc.sh)"},
    deps = [
        ":kdc_test_util",
        ":kerberos",
        ":test_util",
        "@googletest//:gtest_main",
    ],
)

# Kerberos terminate end to end through the bridge, against the throwaway KDC.
cc_test(
    name = "terminate_test",
    srcs = ["terminate_test.cc"],
    data = ["testdata/mit_kdc.sh"],
    env = {"MIT_KDC": "$(rlocationpath testdata/mit_kdc.sh)"},
    deps = [
        ":bridge_test_util",
        ":kdc_test_util",
        ":kerberos",
        ":test_util",
        ":tls_bridge",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    deps = [
        ":config",
        "@googletest//:gtest_main",
    ],
)
