# Multi-packet LOGIN7 under login-only encryption

Size: a small change. Design agreed in conversation on 2026-11-18.

## Intent

The MSSQL proxy module closes connections whose LOGIN7 spans several TDS
packets under login-only encryption (server PRELOGIN `ENCRYPT_OFF`), for
example large Kerberos logins from mssql-jdbc (about 18.6 KB, five packets).
Fix it so the module can be tested with such clients in other environments.

MS-TDS: under login-only encryption, "the first TDS packet of the Login message
MUST be encrypted using TLS/SSL and encapsulated in a TLS/SSL message. All other
TDS packets sent or received MUST be in plaintext." The server rejects a
multi-packet login sent entirely over TLS.

## Goals

1. Observe mode accepts a client LOGIN7 whose first packet comes as TLS and
   whose continuation packets come as plain TDS type 0x10.
2. Terminating mode (TLS bridge) accepts the same from the client.
3. Toward a login-only server, the bridge sends every LOGIN7 with only its first
   TDS packet encrypted and the rest plain. This covers relayed logins and the
   login the Kerberos-terminate path rebuilds.

## Non-goals

- TODO.md item 2 (podman build, `ENVOY_BIN`, the manual end-to-end script).
- Changes to full-encryption legs or to single-packet logins (their bytes on
  the wire stay the same).

## Anti-goals

- Accepting other plain packet types after TLS under login-only encryption.
- Accepting raw TLS from a login-only server.

## Approaches

- **A. Mirror the client's split** (what TODO.md describes): count the bytes the
  client sent over TLS and encrypt that many toward the server. Rejected: it
  carries a non-conforming client's split (all packets encrypted) through to the
  server, has no answer for a plain client upgraded to login-only toward the
  server, and does not cover the Kerberos-terminate path, whose login is rebuilt.
- **B. Fixed rule toward a login-only server: first packet encrypted, rest
  plain.** Chosen: it is the MS-TDS rule, covers relay and terminate paths with
  one rule, and needs no state carried from the client leg.

The Envoy contrib `mssql_proxy` filter was checked: it assumes full encryption
(feeds all client bytes into TLS, encrypts the whole LOGIN7 upstream) and has no
login-only handling, so there is nothing in it to stay consistent with.

## Design

- `tds_connection.cc`, `ConnectionTracker::onLaterUnit`, `Stage::Tls`: under
  login-only, while the server has not answered the login, a plain client TDS
  packet of type LOGIN7 is accepted in the TLS stage. Once a plain LOGIN7 packet
  with EOM has been seen, further plain LOGIN7 packets are rejected. Other plain
  types are rejected as before. (The tracker cannot decrypt the first packet, so
  it cannot tell whether that packet already ended the login; this window is
  accepted, observe mode does not enforce authentication.)
- `tls_bridge.cc`, `TlsBridge::onWireUnit`, `Stage::Tls` (client leg): under
  login-only, a plain LOGIN7 packet is read as part of the same message only
  while LOGIN7 is being read (`login_` unset), its first packet has already come
  over TLS, and no TLS-carried packet is partially buffered
  (`plain_[i].bufferedBytes() == 0`). The complete message still goes through
  `parseLogin7`.
- `tls_bridge.cc`, `TlsBridge::forward`: the MS-TDS rule, stated by position
  rather than by packet type. On a login-only server leg, the first TDS packet
  sent after the TLS handshake is encrypted (its length taken from its header);
  a flag is then set and everything after it on that leg goes plain. Bytes held
  in `pending_to_server_` until the server's TLS leg is ready go through the
  same rule when flushed. The existing "encrypt until the server answers plain"
  logic is replaced by this for login-only server legs.

## Risks

1. **Later LOGIN7 packets travel plain toward the server** (end of an SSPI blob,
   fields placed after it, a FedAuth token in the feature extension). This is
   what the spec requires and what compliant clients send. A client that
   encrypted every packet is now re-split; the server would have rejected its
   login otherwise. Rebuilt Kerberos logins keep the client's field order and
   carry no password.
2. **Our spec reading vs. real servers.** Unit tests run against the in-repo fake
   server, so they prove consistency with our reading only. Mitigated by the
   real-server test below.
3. **Choosing the encrypted bytes in a shared `forward()`.** Mitigated by the
   position rule (first packet after the handshake, then a flag), which does not
   depend on callers or on packet types and covers the pending flush.
4. **Plain packets on the client leg in terminating mode.** Bounded by the
   conditions above; a plain first packet (downgrade) is still rejected. Plain
   continuations can be altered in transit, which is inherent to login-only.
5. **Observe mode's limited view.** Bounded by accepting plain LOGIN7 only until
   the server's response and only until a plain EOM; impact is limited to
   miscounted connections.
6. **Behaviour changes.** Single-packet logins and full-encryption legs keep the
   same bytes on the wire. Existing tests that expect a multi-packet LOGIN7 fully
   encrypted toward a login-only server are updated. A client pipelining data
   after LOGIN7 before the server answers now has it sent plain, as the spec
   says.

## Tests

- `tds_test.cc`: login-only accepts plain LOGIN7 continuations after TLS; rejects
  other plain types after TLS; rejects a plain LOGIN7 after a plain EOM one.
- `tls_bridge_test.cc`: client sends first packet over TLS and the rest plain;
  the server receives the first packet encrypted and the rest plain, with the
  password never in clear. A client that encrypts every packet is re-split the
  same way. A single-packet login is unchanged. A plain first LOGIN7 packet and a
  plain packet while a TLS-carried packet is half-read are both rejected. A
  login held in `pending_to_server_` is split the same way when flushed.
- `terminate_test.cc`: a Kerberos-terminated login large enough to span packets
  reaches a login-only server with only its first packet encrypted.
- `tests/mssql_server_test.sh`: a small raw client sends a LOGIN7 split into
  512-byte packets, first packet over TLS and the rest plain, under login-only
  encryption, to the SQL Server 2025 container: directly, through the module in
  observe mode, and through it terminating TLS. All three must log in. This
  checks B against a real server without needing Kerberos.

## Left to the builder

- The raw client's language and form (Python with the standard library is the
  likely fit, since the test already needs python3).
- Exact test fixture shapes and how a large Kerberos token is produced in the
  terminate test.
