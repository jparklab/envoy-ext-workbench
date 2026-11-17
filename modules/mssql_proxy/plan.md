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
- [x] A real MARS client in the server test: unixODBC `isql` with ODBC 17,
      `MARS_Connection=yes;Encrypt=no` (login-only, so SMP is visible to the
      module), recorded as `testdata/odbc17_mars.tds`
- [x] Packet size: hard cap at the TDS maximum (32767)
- [x] Follow the ENVCHANGE packet-size token in the login response when it is
      visible (encryption none or login-only): `scanLoginResponse` walks the
      login tokens (SSPI, ERROR, INFO, LOGINACK, ENVCHANGE, FEATUREEXTACK,
      SESSIONSTATE, FEDAUTHINFO, RETURNSTATUS, DONE) and stops quietly at any
      other token; Phase 5 builds on it. Server test negotiates 512-byte packets
      and pulls a multi-packet result through the enforced limit.

Kerberos and NTLM need a domain controller; they are tested in Phase 5.

## Phase 3: PRELOGIN and TLS

- [x] `filter_config` (JSON, as a `google.protobuf.Struct` or a `StringValue`;
      parsed with Envoy's `@nlohmann_json`, unknown keys rejected): `tls`
      with `cert_file`, `key_file`, `upstream_ca_file`, `upstream_server_name`,
      `upstream_verify` (`config.h`). Without `tls` the module stays observe-only
      (Phase 2 tracker). Routing rules (Phase 4) and keytab path and policy
      (Phase 5) are added as those phases land. Secrets come from files: the
      SDK's secret subscription appears to be HTTP-filter only
- [x] PRELOGIN option parse/rewrite (ENCRYPTION): forwarded as is so both legs
      negotiate the same mode, except the client-certificate bit (0x80), which is
      cleared: a certificate login authenticates in the TLS handshake, which now
      ends at the proxy (`mssql_proxy_client_cert_cleared_total`)
- [x] TLS termination toward the client and origination toward the server, inside
      TDS PRELOGIN packets (`TlsBridge`, BoringSSL with memory BIOs). Both
      handshakes run at once; client data waits for the server's to finish.
      TLS 1.2 only (TDS 7.x clients use 1.2 there), no resumption. Upstream
      verification on by default; every certificate in `upstream_ca_file` is a
      trust anchor, so a server's own self-signed certificate can be pinned
      (typical SQL Server certificates lack keyCertSign and don't verify as their
      own issuer under BoringSSL)
- [x] Re-encrypt all packet types: decrypted streams are split into TDS/SMP units
      (validated, packet size enforced, login response scanned) and re-encrypted
      whatever their type; login-only goes back to plain TDS on both legs after
      LOGIN7
- [x] Tests: unit tests run a simulated client and server with real TLS through
      the bridge (login-only, full, none, MARS, LOGIN7 held for the server's
      handshake, client-cert bit, untrusted certificate, name check, malformed
      data, chunk sizes 1..1000); `tests/mssql_server_test.sh` runs every client
      mode observe-only and then terminating, checking TLS was terminated and
      LOGIN7 read on every TDS 7.x connection

Not done here, left for later:
- Certificate reload without an Envoy restart (files are read at config load).
- Client certificate authentication through the proxy (the bit is cleared).
- The module only works when it sees the client's PRELOGIN; it still answers
  nothing itself (A2 is Phase 4).

## Phase 4: LOGIN7 routing (A2)

LOGIN7 arrives only after the server has answered PRELOGIN, so in plain case A
the backend is already chosen and connected by then. Routing on LOGIN7 fields
therefore needs A2 (the proxy answers PRELOGIN itself), which needs Phase 3's
TLS. Without A2, routing can only use the listener, client IP, or PRELOGIN's
instance name (module holds PRELOGIN until read); strict clients can use SNI/ALPN
on their own chain.

- [x] `upstream_connect_mode: ON_DOWNSTREAM_DATA` with `max_early_data_bytes`, and
      runtime flag `envoy.reloadable_features.tcp_proxy_delay_route_selection:
      true` (`configs/mssql_proxy_routing.yaml`). tcp_proxy connects on its
      first `onData`, even an empty one, so the module returns Stop (and sends
      nothing on) until it has routed
- [x] Answer the client's PRELOGIN locally and complete client-side TLS: the
      answer mirrors a SQL Server without forced encryption (NOT_SUP -> NOT_SUP,
      OFF -> OFF, ON -> ON), accepts MARS when asked, reports the instance as
      valid, VERSION 16.0.2000. Enabled by `routing` in `filter_config`, which
      requires `tls`
- [x] Bounds-checked LOGIN7 parse (`login7.h`: user, database, server name, app
      name, host, library, language, TDS version, packet size, integrated
      auth flag; the password is never decoded). Read in every terminating
      mode, not only when routing; a malformed LOGIN7, or anything else as the
      client's first message, closes the connection
- [x] Set `envoy.tcp_proxy.cluster` from LOGIN7 fields per `filter_config`
      routing rules (first match wins; exact match ignoring ASCII case on
      database, user, server_name, app_name, client_host, library; empty match
      = catch-all), then release data to `tcp_proxy` so it connects. No match:
      tcp_proxy's own cluster (`mssql_proxy_routed_total` /
      `mssql_proxy_unrouted_total`)
- [x] Send the client's PRELOGIN upstream (client-cert bit cleared; ENCRYPTION
      raised from NOT_SUP to OFF, so the login is always encrypted toward the
      server), complete server-side TLS, consume the server's PRELOGIN
      response, forward the held LOGIN7, relay everything after. The two legs
      may now differ in encryption mode (e.g. login-only toward the client,
      full toward a server that forces encryption); each unit is re-encoded
      for the leg it leaves on
- [x] Keep the local PRELOGIN response consistent with the server: closed as
      incompatible (`mssql_proxy_server_incompatible_total`) when the server
      refuses MARS the client was given, rejects the instance name, asks for
      federated authentication (NONCE/FEDAUTHREQUIRED), or would take the login
      unencrypted while the client encrypts it
- [x] Access logging: LOGIN7 fields as dynamic metadata under `mssql_proxy`
      (user, database, server_name, app_name, client_host, client_library,
      auth, tds_version, and cluster when routed), usable as
      `%DYNAMIC_METADATA(mssql_proxy:database)%`
- [x] Integration test: `tests/mssql_server_test.sh` "route" pass runs every
      client through the routing config plus two `-d tempdb` logins (ODBC 17
      login-only, ODBC 18 full), checks the per-cluster upstream connection
      counts and the access log

Not done here, left for later:
- Federated (Entra ID) authentication with routing: the local PRELOGIN answer
  can't promise FEDAUTHREQUIRED/NONCE before the server is chosen; such logins
  are closed as incompatible. Case A (no `routing`) still forwards them.
- A deadline for LOGIN7: before routing there is no upstream, so tcp_proxy's
  idle timeout may not apply; a client that stops after PRELOGIN holds the
  connection. Needs a module timer (SDK scheduler) or a listener-level limit.
- Encryption policy toward clients (e.g. require encryption) and a
  configurable PRELOGIN VERSION.
- Matching beyond exact strings (prefix/regex), and rejecting logins that
  match no route instead of using tcp_proxy's cluster.

## Phase 5: Authentication

Three integrated-login options, chosen per mechanism in `filter_config`:

1. Kerberos `read_ticket`: decrypt only the client's ticket with the keytab of
   the service the client targeted, learn the principal, and forward LOGIN7
   unchanged. The proxy never runs an acceptor, so it records nothing in a
   replay cache and shares none with the server; the server does the full check.
2. Kerberos `terminate`: the proxy is the Kerberos acceptor (its own SPN and
   keytab), answers the client itself, and logs in to SQL Server with a new
   Kerberos exchange using the proxy's credentials, either delegating (SQL
   Server sees the end user) or as the proxy's service account.
3. NTLM `pass_through`: relay the three NTLM messages unchanged and read the
   user from AUTHENTICATE; the server (via its DC) verifies.

All three need the LOGIN7 and SSPI traffic in plain text, so `auth` needs `tls`
(Phase 3 termination); they work with or without `routing`.

Config sketch (final names settle in 5a):

```yaml
auth:
  kerberos:
    mode: read_ticket            # or terminate; absent: Kerberos relayed unread
    keytab_file: /etc/mssql_proxy/service.keytab
    upstream:                    # terminate only
      identity: delegate         # or service_account
      principal: svc-mssql-proxy@EXAMPLE.COM
      keytab_file: /etc/mssql_proxy/proxy-client.keytab
      spn: MSSQLSvc/sql1.example.com:1433
      cluster_spns: { mssql_tempdb: MSSQLSvc/sql2.example.com:1433 }
  ntlm: pass_through             # or deny
  deny: [ ... ]                  # identities refused with ERROR 18456
```

Library: MIT krb5 / GSS-API (system `libkrb5`, `libgssapi_krb5`; 1.20.1 here),
linked dynamically into the module. Envoy carries no Kerberos code, so there is
no clash. The `.so` then needs those libraries on the Envoy host.

### 5a: Shared pieces

- [x] `auth` config: `ntlm` (pass_through / deny) and `deny`, `auth needs tls`;
      the Kerberos keys and keytab checks come with 5c and 5d
- [x] Bridge: LOGIN7 and client SSPI messages (type 0x11) held until complete
      and checked before they go on; LOGIN7 SSPI data exposed (`cbSSPILong`
      when it doesn't fit 16 bits)
- [x] Token classifier, bounds-checked ASN.1 DER: SPNEGO NegTokenInit /
      NegTokenResp, GSS krb5 framing (OID + TOK_ID) to the Kerberos message, raw
      `NTLMSSP\0`; the mechanism is that of the token carried, so a SPNEGO
      fallback from Kerberos to NTLM is seen
- [x] Login-response scan reports the server's SSPI token and ERROR number;
      the login result (succeeded / failed) follows from it
- [x] Deny: ERROR 18456 + DONE to the client (encrypted as its leg needs),
      then close with flush; nothing of the refused login reaches the server,
      and with routing no upstream connection is opened. Only early denial: every
      identity is known before the server's verdict, so replacing LOGINACK
      isn't needed
- [x] Dynamic metadata: `auth` (sql / kerberos / ntlm / integrated /
      federated), `identity`, `login_result`, `server_error`; counters per
      result and per method
- [x] Tests: classifier and policy unit tests; bridge tests for refusals in
      every encryption mode (forwarded and local PRELOGIN), multi-packet SSPI
      forwarding and an NTLM fallback refused; the server test refuses a login
      by name in the terminating and routing passes and checks the access log

Not done here: holding the server's login response to EOM before forwarding
(only needed to substitute SSPI tokens, in 5d).

### 5b: NTLM pass-through

The proxy cannot verify NTLM itself and still log the user in: the client's
response is bound to the server's challenge, so only the challenger can check it.
The proxy relays the messages unchanged and reads the identity on the way.

- Flow: LOGIN7 (fIntSecurity, SSPI data = NEGOTIATE) -> server SSPI token (0xED,
  CHALLENGE) -> client SSPI packet (0x11, AUTHENTICATE) -> LOGINACK or ERROR.
- Identity: user, domain and workstation are plaintext fields of AUTHENTICATE.
  It is the client's claim until LOGINACK, verified after (user and domain are
  inputs to the NTLMv2 response).

- [ ] Bounds-checked AUTHENTICATE parse: every field's offset/length validated;
      UTF-16LE when NEGOTIATE_UNICODE was negotiated, OEM otherwise
- [ ] Normalise identity: `DOMAIN\user` vs UPN `user@dns.domain`
- [ ] Never modify NTLM messages or their SPNEGO wrapper (the MIC covers all
      three); hold client traffic until the login result is known
- [ ] `ntlm: deny` refuses NTLM logins early; optional NTLMv1 rejection
      (NtChallengeResponse length 24)
- [ ] Unit tests on synthetic messages; integration test with a SQL Server that
      accepts NTLM (unverified on Linux, see open questions)

Deployment: Extended Protection must be *Off* (AUTHENTICATE carries a channel
binding of the proxy's certificate; *Allowed* already enforces it for clients
that support it) unless the proxy presents the SQL Server's own certificate.
With EPA on, the proxy's SPN must be among SQL Server's accepted NTLM SPNs.

Rejected: the proxy authenticating NTLM itself (own challenge, checked with a DC
via winbind). NTLM can't be delegated, so it would collapse to the shared
service account of option 2 with none of Kerberos's guarantees, and it needs a
domain-joined machine account.

### 5c: Kerberos read_ticket

The client name is never readable on the wire: in the AP-REQ it is inside the
ticket's encrypted part (service key) and the authenticator (session key). The
proxy decrypts the ticket with the keytab (`krb5_decode_ticket`,
`krb5_server_decrypt_ticket_keytab` / `krb5_decrypt_tkt_part`), which yields the
KDC-asserted client principal, the session key and the PAC, then decrypts the
authenticator with the session key to check that its client name matches and
its time is within the clock skew. It records nothing: replays are caught by the
server, which receives the same AP-REQ. A ticket is only issued by the KDC, so
the name is good enough to route and deny on before the server answers; LOGINACK
still decides success.

- [ ] Throwaway MIT realm for tests (`krb5kdc` + `kadmin.local` in a temp dir,
      installed here): KDC, service and client principals, keytabs, `kinit`
- [ ] `auth.kerberos` config (`mode`, `keytab_file`); keytab read at load with
      a key for the service checked
- [ ] Decrypt ticket and authenticator; principal, realm, ticket times
- [ ] Routing: `principal` match key (known at LOGIN7)
- [ ] Optional: PAC group SIDs for policy
- [ ] Unit tests with tickets from the throwaway realm: right principal; wrong
      key, expired ticket, mismatched authenticator rejected
- [ ] Integration test: a SQL Server that shares the service keytab; the
      forwarded login succeeds and the proxy logs the right principal

Deployment: the SPN the client targets (the proxy's host and port) must belong
to the SQL Server's service account, and the proxy holds that account's keytab.
With routing, every backend a Kerberos login can reach must accept that SPN's
tickets (same service account, or SPNs registered to it). EPA must be *Off*: the
authenticator's channel binding is the proxy's certificate.

### 5d: Kerberos terminate

The client authenticates to the proxy (SPN `MSSQLSvc/<proxy>:<port>` registered
to the proxy's own account); the proxy authenticates to SQL Server separately.
The client's ticket never reaches the server, so the proxy keeps its replay cache
on and there is no sharing problem.

Client leg:
- [ ] `gss_accept_sec_context` with the proxy's keytab
      (`gss_acquire_cred_from`, no process environment), SPNEGO
- [ ] Channel binding: pass `tls-server-end-point` of the proxy's certificate,
      so clients that bind are checked rather than broken
- [ ] Answer the client: drop the server's SSPI token from the login response
      and put the proxy's (AP-REP) in its place, re-framing the TDS message
- [ ] NTLM-only clients: relay per `ntlm` (pass_through) or deny

Server leg:
- [ ] `identity: delegate`: with an acceptor credential that can also initiate,
      MIT returns the client's ticket as evidence for S4U2Proxy (constrained
      delegation, Kerberos-only); `gss_init_sec_context` for the backend SPN with
      it. SQL Server sees the end user. Needs AD to let the proxy account
      delegate to the backend SPNs (or RBCD on them) and forwardable tickets
- [ ] `identity: service_account`: `gss_init_sec_context` with the proxy's own
      client keytab; SQL Server sees the proxy account, the proxy logs the user
- [ ] Backend SPN from the routed cluster (`cluster_spns`, default `spn`)
- [ ] Rewrite LOGIN7: replace the SSPI data, fix offsets and lengths (and
      `cbSSPILong`); everything else as the client sent it
- [ ] Channel binding toward the server: `tls-server-end-point` of the server's
      certificate, so EPA *Required* works on this leg
- [ ] Verify the server's AP-REP (mutual auth) before passing LOGINACK on

Async: the GSS calls may contact the KDC (S4U2Proxy, service tickets) and block.
- [ ] Run them on a module-owned worker pool; `readDisable` the connection while
      a call is pending, resume through the filter's `getScheduler()` (both in
      the v1.40.2 SDK); a connection closed meanwhile drops the result
- [ ] Cache the proxy's TGT and service tickets in a per-config memory ccache

- [ ] Tests: unit tests on the LOGIN7 rewrite and login-response substitution;
      integration test with the throwaway realm (service_account against a SQL
      Server set up for it; delegate where the KDC supports constrained
      delegation, see open questions)

### Later

- [ ] Entra token (library 0x01) JWT check against JWKS via `httpCallout`

## Open questions

- TLS library for in-module TLS: settled on `@boringssl//:ssl` linked statically
  into the `.so` (Phase 3). The Envoy binary exports no BoringSSL symbols (only
  module callbacks, Lua and malloc), and modules load with `RTLD_LOCAL`, so the
  module's copy is independent of Envoy's. Still open: a module transport socket
  instead, later.
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
  Phase 5 avoids it in both Kerberos modes: `read_ticket` never runs an
  acceptor, and `terminate` accepts a ticket the server never sees, so the
  proxy's cache stays on and no `KRB5RCACHENAME=none:` fallback is needed.
- Unverified for Kerberos (Phase 5): whether SQL Server on Linux logs in with a
  plain MIT realm (no AD) via `mssql-conf` keytab, else the integration tests
  need AD or Samba AD; whether the MIT KDC (DB2 backend) can grant constrained
  delegation for the `delegate` test, else Samba AD; whether SQL Server checks
  Kerberos channel binding under EPA, and which binding it expects.
- Unverified from the handoff: MIT krb5 SPNEGO acceptance of Windows tokens; whether
  SQL Server checks the SPN on proxied logins; which drivers send the FEDAUTH
  channel binding token.
- Unverified for NTLM: whether SQL Server on Linux accepts NTLM logins (else
  testing needs a Windows SQL Server); which channel binding SQL Server checks
  for EPA, i.e. whether presenting the server's own certificate passes (same
  question as Kerberos); whether drivers (ODBC, SqlClient, JDBC) send raw
  NTLMSSP or SPNEGO-wrapped NTLM; whether the SSPI packet is plaintext under
  login-only encryption (confirm with a capture).
