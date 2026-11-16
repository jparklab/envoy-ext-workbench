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
  answers the client's PRELOGIN itself, reads LOGIN7, then lets `tcp_proxy`
  connect and forwards the real LOGIN7, so the client gets the server's real
  LOGINACK. No forged LOGINACK: without connection sharing there is no reason to
  defer the connect past login, and forging it would mean reproducing the
  server's ENVCHANGEs, collation, packet size and feature acks, while
  Kerberos/Entra logins cannot be replayed later. Revisit only if sharing
  (B2/B3) is ever taken up.
- Only v1.40.2 ABI calls: no `set_upstream_host` or the `main`-only terminal-filter
  stream-info calls.
- Language: C++, built with Bazel in the Envoy workspace (the handoff assumed Rust/rustls).
  TLS termination inside the filter uses an in-module TLS library, most likely
  `@boringssl//:ssl` from Envoy's own dependencies;
  see the open questions below.
- TDS 8.0 strict is out of the module's scope: it starts with a TLS ClientHello
  (`0x16`) while TDS 7.x starts with PRELOGIN (`0x12`), so `tls_inspector` plus a
  filter chain match sends strict clients to a chain without the module, and the
  module only ever sees TDS 7.x. Both protocols are client-first, so the
  inspector never waits on a silent connection.

  ```yaml
  listener_filters:
  - name: envoy.filters.listener.tls_inspector
  filter_chains:
  - filter_chain_match: { transport_protocol: tls }        # TDS 8.0 strict
    filters: [tcp_proxy]                                   # TLS passed through
  - filter_chain_match: { transport_protocol: raw_buffer } # TDS 7.x
    filters: [mssql_proxy, tcp_proxy]
  ```

  Strict clients can be routed only on what the ClientHello shows: SNI
  (`server_names`) and ALPN (`tds/8.0`).

## Scope

- Through the module: TDS 7.x (7.4 tested) with encryption on, required, off (login-only TLS)
  or not supported. MARS passed through.
- Not through the module: TDS 8.0 strict (own `tls_inspector` chain, see above).
- Not in scope: connection sharing; forged LOGINACK.

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

Real-server testing starts here, not in Phase 3: the PoC captures show that real
clients produce login-only encryption (ENCRYPT_OFF, plaintext SQLBatch after
LOGIN7), raw TLS records that are not TDS-framed, and several TDS packets in one
TCP segment. An echo backend or hand-written packets would miss all three.

- [x] `tests/mssql_server_test.sh`: start `mcr.microsoft.com/mssql/server:2025-latest`
      with a random throwaway SA password and certificate, and run queries
      through Envoy for each encryption mode, checking `encrypt_option` and
      which filter chain took the connection; skips when Docker is unavailable:
  - [x] `/opt/mssql-tools` sqlcmd (ODBC 17), default: login-only TLS
  - [x] `/opt/mssql-tools18` sqlcmd (ODBC 18), `-N` mandatory with `-C`: full TLS
  - [x] `/opt/mssql-tools18` sqlcmd `-N s`: TDS 8.0 strict, on the passthrough chain
  - [ ] Optional: go-mssqldb client (`~/playground/golang/sql/sql-test`)
- [x] The server test passes with the Phase 1 passthrough, and keeps passing after
      every later phase

  Found while building it: the SQL Server 2022 Linux image rejects strict
  connections (error 17821) even with a configured certificate
  (microsoft/mssql-docker#878); 2025 accepts them over TLS 1.2. Strict always
  verifies the server certificate (`-C` is ignored), so the test trusts its
  generated certificate via `SSL_CERT_FILE`. The ODBC driver matches the host
  name against DNS SANs, so the certificate lists `127.0.0.1` as a DNS name, and
  `tcp:localhost` does not connect at all with ODBC 18 here.
- [x] Fixtures from our own container (`testdata/record.sh`): record the module chain's traffic with
      Envoy's tap transport socket (`envoy.transport_sockets.tap`, in our
      binary) during the server test, and convert each direction's bytes into
      `modules/mssql_proxy/testdata/`. The tap needs no privileges (packet
      capture needs the `wireshark` group or sudo) and records exactly what the
      module sees, per direction. All credentials in the fixtures
      are throwaway. The PoC's pcaps (real logins, Kerberos tickets, real hosts)
      stay local reference only and are never committed.
- [x] Unit-test harness for module code that doesn't need Envoy: `:tds` library
      and `tds_test` (`cc_test` with `@googletest`), run by `scripts/test.sh`
- [x] Listener in `configs/mssql_proxy.yaml`: `tls_inspector`, a `tls` chain
      with only `tcp_proxy`, and a `raw_buffer` chain with the module
- [x] Encryption state machine for TDS 7.x, driven by the PRELOGIN exchange:
  - [x] Encryption on/required: TLS handshake carried in PRELOGIN packets, then
        raw TLS records (not TDS-framed) passed through untouched
  - [x] Encryption off (login-only TLS): same handshake, LOGIN7 as TLS records,
        then plain TDS packets resume
  - [x] Encryption not supported on either side: plain TDS throughout
        (unit-tested only; none of the test clients produces it)
- [x] 8-byte header parse; reassemble across split reads
- [x] Multi-packet messages up to EOM; several packets in one read
- [x] Reject TDS lengths < 8 or > 32767, TLS records > 2^14 + 2048, bad SMP lengths
- [x] Framer unit tests run on the captured fixtures as well as hand-built cases
- [x] Wire the framer into onRead/onWrite, still forwarding bytes unchanged; done
      only when every encryption mode in the server test still passes

- [x] MARS: when PRELOGIN negotiates it, the post-login stream is SMP packets
      (first byte `0x53`, 16-byte header) wrapping TDS; recognise them and pass
      through opaquely. Parse SMP only if a later phase needs post-login
      inspection. (Unit-tested only.)
- [ ] A real MARS client in the server test (sqlcmd doesn't use MARS; e.g.
      ODBC with `MARS_Connection=yes`, or go-mssqldb), with encryption none or
      login-only so SMP is visible to the module
- [x] Packet size: hard cap at the TDS maximum (32767)
- [ ] Follow the ENVCHANGE packet-size token in the login response when it is
      visible (plaintext); needs a token-stream parser, shared with Phase 5's
      login-response parsing

Kerberos and NTLM need a domain controller; they are tested in Phase 5.

## Phase 3: PRELOGIN and TLS

- [ ] `filter_config` (JSON in a `StringValue`): TLS certificate and key paths
      now; routing rules (Phase 4) and keytab path and policy (Phase 5) added as
      those phases land. Secrets come from files: the SDK's secret subscription
      appears to be HTTP-filter only. JSON parser: one Envoy already carries
      (check which, e.g. nlohmann_json)
- [ ] PRELOGIN option parse/rewrite (ENCRYPTION)
- [ ] TLS termination toward the client and origination toward the server, inside TDS PRELOGIN packets
- [ ] Re-encrypt all packet types

## Phase 4: LOGIN7 routing (A2)

LOGIN7 arrives only after the server has answered PRELOGIN, so in plain case A
the backend is already chosen and connected by then. Routing on LOGIN7 fields
therefore needs A2 (the proxy answers PRELOGIN itself), which needs Phase 3's
TLS. Without A2, routing can only use the listener, client IP, or PRELOGIN's
instance name (module holds PRELOGIN until read); strict clients can use SNI/ALPN
on their own chain.

- [ ] `upstream_connect_mode: ON_DOWNSTREAM_DATA` with `max_early_data_bytes`, and
      runtime flag `envoy.reloadable_features.tcp_proxy_delay_route_selection:
      true` (checked in `tcp_proxy.cc`: without it the route is picked at
      connection open even in this mode, before filter state is set)
- [ ] Answer the client's PRELOGIN locally and complete client-side TLS (Phase 3)
- [ ] Bounds-checked LOGIN7 parse (user, database, server name, app name,
      library type, requested packet size)
- [ ] Set `envoy.tcp_proxy.cluster` from LOGIN7 fields per `filter_config`
      routing rules, then release data to `tcp_proxy` so it connects
- [ ] Send the module's own PRELOGIN upstream, complete server-side TLS, consume
      the server's PRELOGIN response (the client already has one), forward the
      real LOGIN7 re-encrypted, relay everything after unchanged
- [ ] Keep the local PRELOGIN response consistent with what the server will
      accept (version, encryption, MARS, FEDAUTHREQUIRED: the client builds LOGIN7
      feature extensions from it); close with an error if the server's answer
      is incompatible
- [ ] Access logging: LOGIN7 fields as dynamic metadata under `mssql_proxy`
      (user, database, server name, app name, client host), usable as
      `%DYNAMIC_METADATA(mssql_proxy:database)%` in access logs
- [ ] Integration test with two backend clusters selected by LOGIN7 database

## Phase 5: Authentication

- [ ] Log the claimed identity per login type, as dynamic metadata too (identity,
      auth type, login result)
- [ ] Allow/deny policy with TDS 18456 error
- [ ] Entra token (library 0x01) JWT check against JWKS via `httpCallout`

### Kerberos: read-the-ticket model (preferred)

The client name is never readable on the proxy's path: in the AP-REQ (LOGIN7
SSPI data) it is inside the ticket's encrypted part (service key) and the
authenticator (session key); LOGIN7's user/password fields are empty for
integrated auth. So the proxy needs the service keytab just to learn who the
user is.

It only needs to decrypt the ticket, not run a full `gss_accept_sec_context`.
Decrypting the ticket with the keytab key (MIT krb5 lower-level APIs, e.g.
`krb5_decrypt_tkt_part`) yields the KDC-asserted client name and the PAC, and
skips the authenticator check, which is what records into the replay cache. It
does not prove the sender holds the session key (a stolen ticket decrypts too),
but the server verifies the authenticator, so, as with NTLM, the name is a claim
until the server returns LOGINACK and verified after. Kerberos and NTLM then
share one model: read identity in transit, trust it on the server's verdict.

- [ ] Unwrap SPNEGO (ASN.1 DER) to the raw krb5 AP-REQ; bounds-checked
- [ ] Decrypt the ticket with the keytab key; extract client principal and realm
- [ ] Optional: extract PAC group SIDs for policy
- [ ] Deny early on the ticket's client name; trust it only after LOGINACK (shares
      the server login-response parser with NTLM)
- [ ] Integration test against a Linux SQL Server container sharing the proxy's
      keytab: forwarded login succeeds and the proxy logs the right principal

Fallback, only if a full accept is ever needed (e.g. to verify possession
before contacting the server): use `gss_accept_sec_context` and disable the
proxy's replay cache.

- [ ] The module sets `KRB5RCACHENAME=none:` (MIT krb5 >= 1.18;
      `KRB5RCACHETYPE=none` on older) in config init, before any GSS call,
      without overriding a value the operator already set
- [ ] Test: forwarded login succeeds with the replay cache disabled, and fails as
      a replay with it enabled (confirms whether SQL Server shares MIT's rcache)

### NTLM: relay model

The proxy cannot verify NTLM itself and still log the user in: the client's
response is bound to the server's challenge, so only the challenger can check it.
The proxy therefore relays the three NTLM messages unchanged and reads the
identity on the way; the server (via its DC) does the verification.

- Flow: LOGIN7 (fIntSecurity, SSPI data = NEGOTIATE) -> server SSPI token (0xED,
  CHALLENGE) -> client SSPI packet (type 0x11, AUTHENTICATE) -> LOGINACK or
  ERROR 18456.
- Identity: user, domain and workstation are plaintext fields of AUTHENTICATE
  (only TLS protects them). It is the client's claim until the server returns
  LOGINACK; after that it is verified, because user and domain are inputs to the
  NTLMv2 response.
- Policy: deny early on the claimed name (safe: a false claim can only cause a
  deny), and deny late by replacing LOGINACK with ERROR 18456 + DONE and closing
  both sides. Forward no client traffic upstream until the login result is known.

- [ ] Client side: parse SSPI data in LOGIN7 and SSPI packets (0x11); raw
      NTLMSSP (`NTLMSSP\0`) or SPNEGO-wrapped (ASN.1 DER)
- [ ] Bounds-checked AUTHENTICATE parse: every field's offset/length validated;
      UTF-16LE when NEGOTIATE_UNICODE was negotiated, OEM code page otherwise
- [ ] Normalise identity: `DOMAIN\user` vs UPN `user@dns.domain` with empty
      domain; NetBIOS vs DNS domain mapping for policy
- [ ] Server side: parse the login response token stream (SSPI 0xED, LOGINACK
      0xAD, ERROR 0xAA, ENVCHANGE 0xE3, DONE 0xFD) and hold it until EOM to see
      the outcome (shared with Kerberos, which also needs the server's verdict)
- [ ] Never modify NTLM messages or their SPNEGO wrapper: the NTLMv2 MIC covers
      NEGOTIATE, CHALLENGE and AUTHENTICATE
- [ ] Optional policy: reject NTLMv1 (NtChallengeResponse length 24)
- [ ] Integration test with a SQL Server that accepts NTLM

Requirements on the deployment:

- Extended Protection: AUTHENTICATE carries a channel binding hash of the TLS
  certificate the client saw (the proxy's). EPA *Allowed* already enforces it for
  clients that support it, so both *Allowed* and *Required* break unless EPA is
  *Off* or the proxy presents the SQL Server's own certificate.
- Service binding: AUTHENTICATE names the SPN the client targeted (proxy host and
  port); with EPA on, add it to SQL Server's accepted NTLM SPNs.
- No routing by NTLM user: the username only arrives after the server's
  challenge, i.e. after the backend is chosen. LOGIN7 fields (database, server
  name) can still route.
- With encryption *off* (login-only TLS), the SSPI packet after LOGIN7 should be
  plaintext per the spec, so the identity is readable even without TLS
  termination; with encryption on or TDS 8.0 it needs termination (Phase 3).

Rejected alternative: the proxy authenticates NTLM itself (own challenge,
validated against a DC via Samba winbind / `ntlm_auth`). NTLM cannot be
delegated, so the proxy would then have to log in to SQL Server with a shared
identity, losing per-user permissions and auditing, and it needs a domain-joined
machine account.

## Open questions

- TLS library for in-module TLS: `@boringssl//:ssl` linked statically into the
  `.so` is the default choice. Checked on the v1.40.2 build: the Envoy binary
  exports no BoringSSL symbols (only module callbacks, Lua and malloc), and modules
  load with `RTLD_LOCAL`, so the module's copy is independent of Envoy's. Still
  open: a module transport socket instead, later.
- Can `startUpstreamSecureTransport` (in the v1.40.2 C++ SDK) replace in-module TLS
  toward the server? TDS wraps the TLS handshake inside PRELOGIN packets, so likely
  not for TDS 7.x, but it may work for TDS 8.0 (strict encryption, TLS first).
- TDS 8.0 strict clients bypass the module: no LOGIN7 routing, identity logging
  or authentication policy. If authentication is meant as access control, a
  client can avoid it by choosing strict mode. Options: deny strict clients (no
  route on the `tls` chain, or allow only specific SNIs), or terminate TLS on that
  chain with Envoy's own `DownstreamTlsContext` (strict is ordinary TLS from byte
  one), re-originate TLS upstream with `UpstreamTlsContext`, and run the module
  there on plain TDS 8.0, with no in-module TLS code.
- Kerberos replay cache: the proxy verifies the client's AP-REQ, then forwards the
  same LOGIN7 so the server verifies it too. If both record the authenticator in
  one replay cache, the server rejects the login as a replay. MIT krb5 >= 1.18
  keeps one cache file per uid (`/var/tmp/krb5_<uid>.rcache2`), so this can only
  bite when the proxy runs on the same host, as the same uid, as a SQL Server that
  uses MIT krb5. A remote backend is never affected. Disabling the proxy's cache
  is safe: the server still does its own replay check. The PoC's
  `MSSQL_NOTE.md` sets `KRB5RCACHE=none`, which MIT krb5 does not read (only
  `KRB5RCACHENAME`, `KRB5RCACHETYPE`, `KRB5RCACHEDIR`), so the PoC never
  actually disabled it; its backend did not use Kerberos, which hid this. The
  preferred read-the-ticket model (Phase 5) never touches the replay cache, so
  this only applies to the full-accept fallback.
- Unverified from the handoff: MIT krb5 SPNEGO acceptance of Windows tokens; whether
  SQL Server checks the SPN on proxied logins; which drivers send the FEDAUTH
  channel binding token.
- Unverified for NTLM: whether SQL Server on Linux accepts NTLM logins (else
  testing needs a Windows SQL Server); which channel binding SQL Server checks
  for EPA, i.e. whether presenting the server's own certificate passes (same
  question as Kerberos); whether drivers (ODBC, SqlClient, JDBC) send raw
  NTLMSSP or SPNEGO-wrapped NTLM; whether the SSPI packet is plaintext under
  login-only encryption (confirm with a capture).
