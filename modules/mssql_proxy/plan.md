# mssql_proxy plan

Reimplement the C++ PoC TDS proxy (`contrib/mssql_proxy` on the
`CHECKPOINT/20250314_working_version_20250320` branch of the private Envoy checkout)
as a C++ dynamic-module network filter against the v1.40.2 ABI. Start with a
non-sharing proxy: case A, then A2.

## Decisions carried over from the handoff

- No connection sharing in a dynamic module: the v1.40.2 ABI has no pool-lease or
  raw upstream TCP callback. Sharing is deferred (module-owned sockets, or a C++
  extension).
- Case A: this filter sits in front of `tcp_proxy` and uses read/write hooks, buffer
  ops, inject calls, metrics, and filter state `envoy.tcp_proxy.cluster` for backend
  selection. That needs runtime flag
  `envoy.reloadable_features.tcp_proxy_delay_route_selection: true` in
  `layered_runtime` (it defaults to false).
- Case A2: `tcp_proxy` with `upstream_connect_mode: ON_DOWNSTREAM_DATA`; the module
  answers PRELOGIN and LOGIN7 itself and holds data until the first query.
- Only v1.40.2 ABI calls: no `set_upstream_host` or the `main`-only terminal-filter
  stream-info calls.
- Language: C++, built with Bazel in the Envoy workspace (the handoff assumed Rust/rustls).
  TLS termination inside the filter uses an in-module TLS library, most likely
  `@boringssl//:ssl` from Envoy's own dependencies;
  see the open questions below.

## Design rules (from the PoC review)

- Parse whole TDS messages with a state machine that buffers until the EOM bit; never
  drain more than what was consumed.
- Bounds-check every client- and server-supplied length (the PoC's LOGIN7 parse has
  a stack overflow into a 4096-byte buffer).
- Pass unknown packet types through unchanged; under TLS re-encrypt every type, not
  just SQLBatch/LOGIN7.
- A malformed server message closes the connection; it never crashes Envoy.
- Deny a login by sending TDS ERROR 18456 + DONE, then close.

## Phase 1: Passthrough scaffold

- [x] `modules/mssql_proxy` network filter in front of `tcp_proxy`, passthrough only
- [x] Connection and byte counters
- [x] `tests/mssql_proxy_test.sh`: bytes pass unchanged through an echo backend

## Phase 2: TDS framer (test-first)

- [ ] Unit-test harness for module code that doesn't need Envoy (`cc_test` with `@googletest`, SDK fakes from `sdk_fake`)
- [ ] 8-byte header parse; reassemble across split reads
- [ ] Multi-packet messages up to EOM
- [ ] Reject lengths < 8 or > negotiated packet size
- [ ] Wire the framer into onRead/onWrite, still forwarding bytes unchanged

## Phase 3: PRELOGIN and TLS

- [ ] SQL Server container (`mcr.microsoft.com/mssql/server`) and `sqlcmd`/ODBC test client
- [ ] PRELOGIN option parse/rewrite (ENCRYPTION)
- [ ] TLS termination toward the client and origination toward the server, inside TDS PRELOGIN packets
- [ ] Re-encrypt all packet types

## Phase 4: LOGIN7 and backend selection

- [ ] Bounds-checked LOGIN7 parse (user, database, server name, library type)
- [ ] Set `envoy.tcp_proxy.cluster` from LOGIN7 fields; enable the runtime flag
- [ ] Integration test with two backend clusters

## Phase 5: Deferred connect (A2)

- [ ] `upstream_connect_mode: ON_DOWNSTREAM_DATA`
- [ ] Forged PRELOGIN/LOGINACK responses; replay login upstream on first query

## Phase 6: Authentication

- [ ] Log the claimed identity per login type
- [ ] Allow/deny policy with TDS 18456 error
- [ ] Kerberos verification with a keytab
- [ ] Entra token (library 0x01) JWT check against JWKS via `httpCallout`

## Open questions

- TLS library for in-module TLS: `@boringssl//:ssl` linked statically into the
  `.so` is the default choice. Checked on the v1.40.2 build: the Envoy binary
  exports no BoringSSL symbols (only module callbacks, Lua and malloc), and modules
  load with `RTLD_LOCAL`, so the module's copy is independent of Envoy's. Still
  open: a module transport socket instead, later.
- Can `startUpstreamSecureTransport` (in the v1.40.2 C++ SDK) replace in-module TLS
  toward the server? TDS wraps the TLS handshake inside PRELOGIN packets, so likely
  not for TDS 7.x, but it may work for TDS 8.0 (strict encryption, TLS first).
- Unverified from the handoff: MIT krb5 SPNEGO acceptance of Windows tokens; whether
  SQL Server checks the SPN on proxied logins; which drivers send the FEDAUTH
  channel binding token.
