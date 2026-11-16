# mssql_proxy plan tracker

Progress log against plan.md.

## Phase 1: Passthrough scaffold

- [x] 2026-11-16: passthrough filter, counters, and echo-backend integration test; `scripts/test.sh` passes (2/2)

- [x] 2026-11-16: modules switched from CMake to Bazel in the Envoy workspace (`scripts/bazel.sh`, `@workbench`); tests still pass (2/2)
- [x] 2026-11-16: plan reviewed and revised: TDS 8.0 strict on its own chain, encryption-aware framer, real-server test from Phase 2, LOGIN7 routing merged into A2 after TLS, forged LOGINACK dropped, Kerberos/NTLM read-in-transit models, scope and gaps filled

## Phase 2: TDS framer (test-first)

- [x] 2026-11-16: listener split with `tls_inspector`; `tests/mssql_server_test.sh` passes for ODBC 17 login-only TLS, ODBC 18 mandatory TLS (module chain) and ODBC 18 strict (passthrough chain) against SQL Server 2025; `scripts/test.sh` 3/3
- [x] 2026-11-16: fixtures recorded through Envoy's tap (`testdata/record.sh`); `:tds` library (unit splitter, PRELOGIN parser, encryption-mode tracker) with 27 unit tests including fixture replay at chunk sizes 1..1000; wired into the filter (observe-only, closes on protocol errors); server test checks the module saw login-only and full encryption with no errors; `scripts/test.sh` runs unit tests too
- [ ] Next: real MARS client test; ENVCHANGE packet size (token-stream parser)
