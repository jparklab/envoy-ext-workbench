load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

# MIT Kerberos, built from source with Envoy's toolchain and linked statically
# into the module that uses it: the module needs no Kerberos library on the
# host, and every deployment runs the same release. src/ is the release's src/
# directory, fetched and checked by scripts/bazel.sh (gitignored).
#
# - Builtin crypto, so libk5crypto doesn't pull in OpenSSL next to BoringSSL.
# - -fvisibility=hidden: Kerberos symbols stay private to the module, so they
#   can't collide with a system libkrb5 that something else in the process
#   loads.
# - Static builds have their plugins compiled in and load none from the host
#   (e.g. no KCM credential caches or SSSD locator); keytabs and FILE: and
#   MEMORY: credential caches work, and krb5.conf is read as usual.

filegroup(
    name = "srcs",
    srcs = glob(["src/**"]),
)

configure_make(
    name = "build",
    configure_options = [
        "--enable-static",
        "--disable-shared",
        "--with-crypto-impl=builtin",
        "--with-prng-alg=os",
        "--disable-nls",
        "--disable-rpath",
        "--without-keyutils",
        "--without-ldap",
        "--without-lmdb",
        "--without-tcl",
        "--without-libedit",
        "--without-readline",
        "--without-system-verto",
        # Configuration comes from /etc/krb5.conf (or KRB5_CONFIG) only. The
        # sysconfdir paths (a second krb5.conf, the GSS mechanism list) point
        # nowhere rather than into the build sandbox or the host's /etc: GSS
        # mechanism plugins configured there (e.g. gssproxy) are built against
        # the system's libraries and can't bind to this private copy.
        "--sysconfdir=/nonexistent/mit_krb5",
        "--localstatedir=/nonexistent/mit_krb5",
    ],
    copts = [
        "-fPIC",
        "-fvisibility=hidden",
        "-w",
    ],
    lib_source = ":srcs",
    # DNS SRV lookups (res_nsearch) in libkrb5; the plugin loader (dlopen),
    # which a static build still links though it loads nothing by default.
    # On this target, not a wrapper: cc_shared_library drops the link flags of
    # a dependency that brings no libraries.
    linkopts = [
        "-lresolv",
        "-ldl",
    ],
    # Libraries only: the clients, the KDC and the admin tools aren't needed.
    targets = [
        "-C util all",
        "-C include all",
        "-C lib all",
        "install-mkdirs",
        "-C util install",
        "-C include install",
        "-C lib install",
    ],
    # Link order: each library uses only those after it.
    out_static_libs = [
        "libgssapi_krb5.a",
        "libkrb5.a",
        "libk5crypto.a",
        "libcom_err.a",
        "libkrb5support.a",
    ],
)

alias(
    name = "mit_krb5",
    actual = ":build",
    visibility = ["//visibility:public"],
)
