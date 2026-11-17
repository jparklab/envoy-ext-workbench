# mssql_proxy plan tracker

Progress log against plan.md.

## Phase 1: Passthrough scaffold

- [x] 2026-11-16: passthrough filter, counters, and echo-backend integration test; `scripts/test.sh` passes (2/2)

- [x] 2026-11-16: modules switched from CMake to Bazel in the Envoy workspace (`scripts/bazel.sh`, `@workbench`); tests still pass (2/2)
- [x] 2026-11-16: plan reviewed and revised: TDS 8.0 strict on its own chain, encryption-aware framer, real-server test from Phase 2, LOGIN7 routing merged into A2 after TLS, forged LOGINACK dropped, Kerberos/NTLM read-in-transit models, scope and gaps filled

## Phase 2: TDS framer (test-first)

- [x] 2026-11-16: listener split with `tls_inspector`; `tests/mssql_server_test.sh` passes for ODBC 17 login-only TLS, ODBC 18 mandatory TLS (module chain) and ODBC 18 strict (passthrough chain) against SQL Server 2025; `scripts/test.sh` 3/3
- [x] 2026-11-16: fixtures recorded through Envoy's tap (`testdata/record.sh`); `:tds` library (unit splitter, PRELOGIN parser, encryption-mode tracker) with 27 unit tests including fixture replay at chunk sizes 1..1000; wired into the filter (observe-only, closes on protocol errors); server test checks the module saw login-only and full encryption with no errors; `scripts/test.sh` runs unit tests too
- [x] 2026-11-16: real MARS client (isql, ODBC 17) through the module, recorded as a fixture; login-response token scan learns the negotiated packet size and the splitter enforces it; server test adds 512-byte-packet and MARS modes; 37 unit tests; Phase 2 complete

## Phase 3: PRELOGIN and TLS

- [x] 2026-11-17: `filter_config` (`tls` settings from files), TLS termination on both legs inside PRELOGIN packets with re-encryption of every type, client-cert bit cleared; observe-only kept when `tls` is absent; unit tests with simulated TLS peers; server test passes all five client modes observe-only and terminating (TLS terminated and LOGIN7 read on every TDS 7.x connection); Phase 3 complete

## Phase 4: LOGIN7 routing (A2)

- [x] 2026-11-17: local PRELOGIN answer and LOGIN7 read before tcp_proxy connects (ON_DOWNSTREAM_DATA with delayed route selection); per-leg encryption modes; server PRELOGIN compatibility checks; LOGIN7 parser; `routing` rules setting `envoy.tcp_proxy.cluster`; LOGIN7 fields in dynamic metadata; unit tests for parser, routing config and the bridge in local-PRELOGIN mode (same and mixed encryption, MARS, incompatible servers); server test adds a routing pass (every client plus tempdb logins routed to a second cluster, access log checked); Phase 4 complete

## Phase 5: Authentication

- [x] 2026-11-17: plan revised around three options: Kerberos read_ticket (no shared replay cache), Kerberos terminate with re-authentication (delegate or service account, configurable), NTLM pass-through; split into 5a shared pieces, 5b NTLM, 5c read_ticket, 5d terminate
- [x] 2026-11-17: 5a: `auth` config (`ntlm`, `deny`); authentication token classifier (SPNEGO, GSS Kerberos, NTLMSSP); LOGIN7 and SSPI messages held and checked before forwarding; refusals answered with ERROR 18456; login method, identity and result in metadata and counters; unit tests, and the server test refuses a login by name in the terminating and routing passes
- [x] 2026-11-17: 5b: NTLM AUTHENTICATE parsed for the claimed identity (`DOMAIN\user` or UPN), messages relayed unchanged, `ntlm: v2_only` and deny list applied at AUTHENTICATE before it reaches the server; unit and bridge tests on MS-NLMP-shaped messages; no real NTLM test (needs an AD-joined SQL Server)
- [x] 2026-11-17: 5c: Kerberos read_ticket with MIT libkrb5 loaded at run time; AP-REQ/authenticator parsed in the module, ticket decrypted with the keytab, times and authenticator checked, no replay cache; `principal` route key; throwaway MIT realm script; 8 unit tests against a real KDC; the server test reads `alice@TEST.REALM` from a real ODBC 17 Kerberos login (the server itself refuses it: no AD)
- [x] 2026-11-17: MIT Kerberos 1.22.3 built from source (pinned, sha256-checked) and linked statically into the module with hidden symbols, replacing the run-time load of the host's libkrb5; unit and server tests pass on it
- [x] 2026-11-17: 5d: Kerberos terminate: the proxy accepts Kerberos logins with its own SPN and logs in to SQL Server with its own exchange, as its service account or as the client (forwarded TGT; S4U2Proxy as far as the KDC); LOGIN7 rewritten with the proxy's token, the server's AP-REP checked before LOGINACK goes on, the proxy's own AP-REP in its place; GSS steps on a worker pool resumed through the scheduler; optional tls-server-end-point channel binding on both legs; unit, bridge and end-to-end tests against the throwaway realm, and ODBC 17 through terminate in the server test (the server itself refuses: no AD)
