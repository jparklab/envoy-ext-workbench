# mssql_proxy plan tracker

Progress log against plan.md.

## Phase 1: Passthrough scaffold

- [x] 2026-11-16: passthrough filter, counters, and echo-backend integration test; `scripts/test.sh` passes (2/2)

- [x] 2026-11-16: modules switched from CMake to Bazel in the Envoy workspace (`scripts/bazel.sh`, `@workbench`); tests still pass (2/2)
- [x] 2026-11-16: plan reviewed and revised: TDS 8.0 strict on its own chain, encryption-aware framer, real-server test from Phase 2, LOGIN7 routing merged into A2 after TLS, forged LOGINACK dropped, Kerberos/NTLM read-in-transit models, scope and gaps filled

## Phase 2: TDS framer (test-first)

- [x] 2026-11-16: listener split with `tls_inspector`; `tests/mssql_server_test.sh` passes for ODBC 17 login-only TLS, ODBC 18 mandatory TLS (module chain) and ODBC 18 strict (passthrough chain) against SQL Server 2025; `scripts/test.sh` 3/3
- [ ] Next: fixtures via Envoy's tap transport socket, then the framer
