# Multi-packet LOGIN7 under login-only encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The MSSQL proxy module accepts and correctly forwards LOGIN7 messages that span several TDS packets under login-only encryption, in observe and terminating modes, including logins the Kerberos-terminate path rebuilds.

**Architecture:** Observe mode (`ConnectionTracker`) and the TLS bridge's client leg accept plain LOGIN7 continuation packets after a TLS-carried first packet. Toward a login-only server, the bridge applies the MS-TDS rule by position: the first TDS packet sent after the TLS handshake goes encrypted, everything after it plain. A raw Python client checks the result against a real SQL Server.

**Tech Stack:** C++20, BoringSSL, GoogleTest, Bazel (`scripts/bazel.sh`), bash + python3 (standard library) for the real-server test.

**Spec:** `docs/superpowers/specs/2026-11-18-login-only-multipacket-login7-design.md`

## Global Constraints

- MS-TDS rule: under login-only encryption, "the first TDS packet of the Login message MUST be encrypted using TLS/SSL ... All other TDS packets sent or received MUST be in plaintext."
- Full-encryption legs and single-packet logins: bytes on the wire unchanged.
- Still rejected: plain packet types other than LOGIN7 after TLS under login-only; raw TLS from a login-only server; a plain first LOGIN7 packet.
- Out of scope: TODO.md item 2 (podman build, `ENVOY_BIN`, `tests/mssql_gcp_kerberos.sh`).
- Commit messages: a subject plus a 2–4 line paragraph on intent; no file lists or mechanisms. End with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Unit tests: `scripts/bazel.sh test @workbench//modules/mssql_proxy:<target> --test_output=errors`.

## Review Focus

1. A login whose first packet is split across several TLS records, followed by plain continuations: the client leg must reassemble the first packet before accepting plain packets (covered by the `Chunks` parameter of `BridgeModes`, 0/1/7/1000-byte deliveries, in Task 2).
2. A plain continuation arriving while the TLS-carried first packet is incomplete must be rejected, not mis-ordered (Task 2, `RejectsPlainLogin7WhileTlsPacketIncomplete`).
3. A login held in `pending_to_server_` because the server's handshake was slow must be split the same way when flushed (Task 3, `HoldsSplitLoginUntilServerHandshakeDone`).
4. After the split login, the session must carry on in plain TDS both ways: the server's plain response must still switch the server leg to plain (Task 3 tests continue with a response and a batch).
5. Local PRELOGIN (`answer_prelogin`) with a full-encryption client and a login-only server: the client's all-encrypted login is re-split toward the server (Task 3, `LocalPrelogin.FullClientLoginOnlyServerSplitsLogin`).

---

### Task 1: Observe mode accepts plain LOGIN7 continuations

**Files:**
- Modify: `modules/mssql_proxy/tds_connection.h` (state near `stage_`, line 96)
- Modify: `modules/mssql_proxy/tds_connection.cc:168-177` (`ConnectionTracker::onLaterUnit`, `Stage::Tls`)
- Test: `modules/mssql_proxy/tds_test.cc` (after `RejectsPlainLoginWhenEncrypting`, line 329)

**Interfaces:**
- Consumes: existing `ConnectionTracker`, `tdsPacket`, `tlsRecord`, `clientPrelogin`, `serverPrelogin` test helpers.
- Produces: nothing used by later tasks.

- [ ] **Step 1: Write the failing tests**

Shared setup in each: `clientPrelogin(0x00)`, `serverPrelogin(0x00)`, then client and server handshake packets as in `FullEncryptionRejectsPlainAfterTls` (`tdsPacket(kTdsPrelogin, true, "\x16\x03\x01 hello")` / `"\x16\x03\x03 hello"`), then `t.onClientData(tlsRecord(0x17, "login7 first packet"))`.

```cpp
TEST(ConnectionTracker, LoginOnlyAcceptsPlainLogin7ContinuationAfterTls) {
  // setup as above
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, false, "second")));
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "third")));
  EXPECT_FALSE(t.onServerData(tdsPacket(kTdsTabularResult, true, loginAck() + done())));
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsSqlBatch, true, "select 1")));
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::LoginOnly);
}

TEST(ConnectionTracker, LoginOnlyStillRejectsOtherPlainTypesAfterTls) {
  // setup as above
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsSqlBatch, true, "select 1")));
}

TEST(ConnectionTracker, LoginOnlyRejectsPlainLogin7AfterItsEnd) {
  // setup as above
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "last")));
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsLogin7, true, "another")));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `scripts/bazel.sh test @workbench//modules/mssql_proxy:tds_test --test_output=errors`
Expected: FAIL in `LoginOnlyAcceptsPlainLogin7ContinuationAfterTls` and `LoginOnlyRejectsPlainLogin7AfterItsEnd` (plain LOGIN7 rejected); `LoginOnlyStillRejectsOtherPlainTypesAfterTls` passes already.

- [ ] **Step 3: Implement**

Add `bool login7_plain_ended_ = false;` to `ConnectionTracker`. In `Stage::Tls`, after the existing "back to plain once the login is answered" branch, accept a unit when all hold: client direction, `mode_ == EncryptionMode::LoginOnly`, `unit.kind == UnitKind::TdsPacket`, `unit.type == kTdsLogin7`, `!login7_plain_ended_`. Set `login7_plain_ended_ = unit.eom`. Stay in `Stage::Tls`. Add a comment that the tracker cannot decrypt the first packet, so a plain LOGIN7 after a single-packet login is not detected.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/bazel.sh test @workbench//modules/mssql_proxy:tds_test --test_output=errors`
Expected: PASS (all of `tds_test`).

- [ ] **Step 5: Commit**

```bash
git add modules/mssql_proxy/tds_connection.h modules/mssql_proxy/tds_connection.cc modules/mssql_proxy/tds_test.cc
git commit  # "Follow multi-packet logins under login-only encryption" + intent paragraph
```

---

### Task 2: Bridge client leg reads plain LOGIN7 continuations

**Files:**
- Modify: `modules/mssql_proxy/tls_bridge.cc:302-326` (`TlsBridge::onWireUnit`, `Stage::Tls`)
- Modify: `modules/mssql_proxy/bridge_test_util.h` (new helpers below)
- Test: `modules/mssql_proxy/tls_bridge_test.cc` (after `BridgeModes.HoldsLoginUntilServerHandshakeDone`, and after `Bridge.RejectsMalformedLogin7`)

**Interfaces:**
- Produces, in `bridge_test_util.h` (namespace `MssqlProxy::test`), used by Task 3:
  - `Login7Fields longLogin()` — a SQL login (default `login7Payload` fields) with `host`, `app` and `library` each 128 `'x'`-style characters, so the payload spans 2 packets at 512 bytes and the password lands in the first packet.
  - `void sendSplitLogin7(Peer& client, std::string_view payload, size_t packet_size)` — builds `makeTdsMessage(kTdsLogin7, payload, packet_size)`, sends its first packet with `sendRaw(..., true)` and the rest with `sendRaw(..., false)`. First packet length from the header's big-endian bytes 2–3.

- [ ] **Step 1: Write the failing tests**

```cpp
TEST_P(BridgeModes, LoginOnlyMultiPacketLogin7WithPlainContinuation) {
  Harness h(kEncOff, kEncOff, GetParam());
  ASSERT_TRUE(h.connect()) << h.message();
  const std::string login7 = login7Payload(longLogin());
  sendSplitLogin7(h.client, login7, 512);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7, 512));
  ASSERT_TRUE(h.bridge.login());
  EXPECT_EQ(h.bridge.login()->user_name, "app_user");
}

TEST(Bridge, RejectsPlainFirstLogin7Packet) {
  Harness h(kEncOff, kEncOff, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(longLogin()), /*over_tls=*/false, 512);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Protocol);
}

TEST(Bridge, RejectsPlainLogin7WhileTlsPacketIncomplete) {
  // First 512-byte packet: only its first 100 bytes over TLS, then a plain
  // LOGIN7 packet. Expect a Protocol error.
}

TEST(Bridge, LoginOnlyStillRejectsOtherPlainTypesDuringLogin7) {
  // First LOGIN7 packet over TLS (eom clear), then plain kTdsSqlBatch.
  // Expect a Protocol error.
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `scripts/bazel.sh test @workbench//modules/mssql_proxy:tls_bridge_test --test_output=errors`
Expected: `LoginOnlyMultiPacketLogin7WithPlainContinuation` FAILs with "plain TDS packet type 0x10 after TLS under login-only encryption"; the three rejection tests pass.

- [ ] **Step 3: Implement**

In `Stage::Tls`, before the existing `app_sent_` branch, accept a plain unit when all hold: `i == kClient`, `leg_mode_[i] == EncryptionMode::LoginOnly`, `unit.kind == UnitKind::TdsPacket && unit.type == kTdsLogin7`, `!login_`, `!login7_message_.empty()` (the first packet came over TLS), `plain_[i].bufferedBytes() == 0`. Pass it to `onPlainUnit(d, unit)` without changing `stage` or `plain_received_`. Comment: some drivers (mssql-jdbc) encrypt only the first LOGIN7 packet, as MS-TDS requires under login-only.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `scripts/bazel.sh test @workbench//modules/mssql_proxy:tls_bridge_test --test_output=errors`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add modules/mssql_proxy/tls_bridge.cc modules/mssql_proxy/bridge_test_util.h modules/mssql_proxy/tls_bridge_test.cc
git commit  # "Accept split logins from clients under login-only encryption" + intent paragraph
```

---

### Task 3: Toward a login-only server, encrypt only the first packet

**Files:**
- Modify: `modules/mssql_proxy/tls_bridge.h` (state near `app_sent_`, line 266; comment on `forward`, line 245)
- Modify: `modules/mssql_proxy/tls_bridge.cc:927-971` (`TlsBridge::forward`)
- Modify: `modules/mssql_proxy/bridge_test_util.h` (new helper below)
- Test: `modules/mssql_proxy/tls_bridge_test.cc`

**Interfaces:**
- Consumes: `longLogin()`, `sendSplitLogin7(...)` from Task 2.
- Produces, in `bridge_test_util.h`: `std::string wireShape(std::string_view wire)` — runs a `StreamSplitter` over a captured wire and returns one character per unit after the PRELOGIN exchange (`TdsPacket` of type `kTdsPrelogin` skipped): `'T'` for a TLS record, `'L'` for a plain LOGIN7 packet, `'P'` for any other plain TDS packet.

- [ ] **Step 1: Write the failing tests**

Each asserts `wireShape(h.to_server_wire)` right after the login is delivered, then has the server answer plain (`loginResponse("4096")`) and checks a following plain `select 1` arrives as in `BridgeModes.LoginOnly`.

```cpp
// Extend Task 2's LoginOnlyMultiPacketLogin7WithPlainContinuation:
  EXPECT_EQ(wireShape(h.to_server_wire), "TL");
  EXPECT_EQ(h.to_server_wire.find(utf16("not-a-real-password")), std::string::npos);

TEST_P(BridgeModes, LoginOnlyMultiPacketLogin7AllEncryptedIsResplit) {
  // h.client.send(kTdsLogin7, login7Payload(longLogin()), true, 512);
  // server.received == makeTdsMessage(kTdsLogin7, payload, 512); shape "TL".
}

TEST_P(BridgeModes, LoginOnlySinglePacketLoginStaysOneRecord) {
  // login7Payload() at 4096 over TLS; shape "T".
}

TEST_P(BridgeModes, HoldsSplitLoginUntilServerHandshakeDone) {
  // As HoldsLoginUntilServerHandshakeDone, but Harness(kEncOff, kEncOff, ...)
  // and sendSplitLogin7(h.client, login7Payload(longLogin()), 512);
  // after the final pump: server.received matches, shape "TL".
}

TEST_P(LocalPrelogin, FullClientLoginOnlyServerSplitsLogin) {
  // Client kEncOn, server kEncOff, answer_prelogin; client sends the long
  // login all over TLS at 512; shape toward the server "TL".
}

TEST(Terminate, LongRebuiltLoginSplitTowardLoginOnlyServer) {
  // TerminateModes setup with kEncOff/kEncOff, login over TLS;
  // t.gss.initiates = {{.token = std::string(6000, 't')}, {.complete = true}};
  // server.received == upstreamLogin(std::string(6000, 't')); shape "TL".
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `scripts/bazel.sh test @workbench//modules/mssql_proxy:tls_bridge_test --test_output=errors`
Expected: the multi-packet tests FAIL on the shape (`"T"` or `"TT"` instead of `"TL"`); `LoginOnlySinglePacketLoginStaysOneRecord` passes.

- [ ] **Step 3: Implement**

Add `bool server_first_packet_sent_ = false;` to `TlsBridge`. In `forward`, replace the `EncryptionMode::LoginOnly` case: when `to == kServer` and `!server_first_packet_sent_`, take the first packet's length from `bytes[2..3]` (big-endian; `protocolError` if `bytes` is shorter than 8 or than that length), encrypt that prefix, set the flag, and send the remainder plain. When the flag is set, everything goes plain. Toward the client under login-only nothing changes (plain). Keep `app_sent_` and `plain_received_` updates as they are (`onWireUnit` relies on them). Update the `forward` comment in `tls_bridge.h` with the MS-TDS rule.

- [ ] **Step 4: Run all module tests**

Run: `scripts/bazel.sh test @workbench//modules/mssql_proxy/... --test_output=errors`
Expected: all six targets PASS. If an existing test expected a multi-packet LOGIN7 fully encrypted toward a login-only server, update its expectation to the split and say so in the task report.

- [ ] **Step 5: Commit**

```bash
git add modules/mssql_proxy/tls_bridge.h modules/mssql_proxy/tls_bridge.cc modules/mssql_proxy/bridge_test_util.h modules/mssql_proxy/tls_bridge_test.cc
git commit  # "Send logins to login-only servers as MS-TDS requires" + intent paragraph
```

---

### Task 4: Real-server check with a split LOGIN7

**Files:**
- Create: `modules/mssql_proxy/testdata/split_login7.py`
- Modify: `tests/mssql_server_test.sh` (header comment; before the `for pass` loop; inside the loop after `odbc17_small_packets`; the `login_only` counts)

**Interfaces:**
- Produces: `python3 -I modules/mssql_proxy/testdata/split_login7.py HOST PORT USER` with the password in `SQLCMDPASSWORD`. Prints `LOGINACK split=<n>` (n = number of LOGIN7 packets) and exits 0 on LOGINACK; prints the server's error text and exits 1 otherwise.

- [ ] **Step 1: Write the client**

Standard library only (`socket`, `ssl`, `struct`). Steps:
1. PRELOGIN with VERSION, ENCRYPTION = `0x00` (off), INSTOPT, THREADID; read the response; require ENCRYPTION `0x00`.
2. TLS handshake with `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`, `check_hostname=False`, `verify_mode=CERT_NONE`, over `MemoryBIO`s; each outgoing flight wrapped in one PRELOGIN (`0x12`) packet; incoming PRELOGIN payloads fed to the incoming BIO.
3. LOGIN7 (TDS 7.4 `0x74000004`, packet size 4096, SQL login): password obfuscated per MS-TDS (swap nibbles, XOR `0xA5`), placed in the data area right after host name and user name so it lands in the first packet. HostName, AppName and CltIntName each 128 characters so the message spans at least 2 packets of 512 bytes. Database `master`.
4. Packetize at 512 bytes (status EOM on the last, packet IDs counting from 1). Send packet 1 through `SSLObject.write` and the resulting raw TLS record(s) unwrapped; send the rest as plain bytes.
5. Read the plain TDS response until EOM; scan for token `0xAD` (LOGINACK) or `0xAA` (ERROR, print its message).

- [ ] **Step 2: Run it directly against the container**

In `mssql_server_test.sh`, after the readiness loop and before the passes:

```bash
out="$(python3 -I "$REPO_ROOT/modules/mssql_proxy/testdata/split_login7.py" 127.0.0.1 "$port" sa 2>&1)" \
  || fail "split LOGIN7 rejected by SQL Server itself: $out"
echo "  ok: SQL Server accepts a LOGIN7 split across packets, first one encrypted"
```

Run: `bash tests/mssql_server_test.sh`
Expected: the new `ok:` line prints (this proves the MS-TDS reading against a real server). Later lines may still fail until step 3.

- [ ] **Step 3: Add it to every pass**

After `odbc17_small_packets`:

```bash
run_mode split_login7 "split LOGIN7, login-only TLS" '^LOGINACK split=[2-9]' module \
  python3 -I "$REPO_ROOT/modules/mssql_proxy/testdata/split_login7.py" 127.0.0.1 11433 sa
```

Raise the `login_only` counts by one (`login_only=3 mars=0`, the `isql` branch to `login_only=4`). The SQL-login and terminated counters follow from `connections`. Add one line to the header comment listing the split-login client.

- [ ] **Step 4: Run the whole real-server test**

Run: `scripts/build-modules.sh && bash tests/mssql_server_test.sh`
Expected: `ok: <pass>: split LOGIN7, login-only TLS` for observe, terminate and route, then `PASS: mssql_server_test`.

- [ ] **Step 5: Run everything**

Run: `scripts/test.sh`
Expected: all unit targets pass, `N test(s), 0 failed`.

- [ ] **Step 6: Commit**

```bash
git add modules/mssql_proxy/testdata/split_login7.py tests/mssql_server_test.sh
git commit  # "Check split logins against a real SQL Server" + intent paragraph
```
