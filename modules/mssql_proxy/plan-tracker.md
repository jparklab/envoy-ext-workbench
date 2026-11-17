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

- [ ] Next up
