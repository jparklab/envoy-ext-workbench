// TlsBridge between a simulated TDS 7.x client and SQL Server. Both peers run
// real TLS (BoringSSL) inside PRELOGIN packets, as the drivers do, so these
// tests check that each leg's handshake completes against the bridge and that
// what one peer sends arrives at the other unchanged in plain text.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "bridge_test_util.h"
#include "gtest/gtest.h"
#include "tds.h"
#include "test_util.h"
#include "tls_bridge.h"

namespace MssqlProxy {
namespace {

using namespace test;

// ---------------------------------------------------------------- contexts

TEST(TlsContexts, RejectsBadSettings) {
  std::string error;
  TlsSettings s = settings();
  s.cert_pem = "not a certificate";
  EXPECT_FALSE(TlsContexts::create(s, error));
  EXPECT_NE(error.find("certificate"), std::string::npos) << error;

  s = settings();
  s.key_pem = serverCert().key_pem;
  EXPECT_FALSE(TlsContexts::create(s, error));
  EXPECT_NE(error.find("private key"), std::string::npos) << error;

  s = settings();
  s.upstream_ca_pem.clear();
  EXPECT_FALSE(TlsContexts::create(s, error)) << "verification needs a CA";
  s.upstream_verify = false;
  EXPECT_TRUE(TlsContexts::create(s, error)) << error;
}

// ---------------------------------------------------------------- modes

class BridgeModes : public ::testing::TestWithParam<size_t> {};

TEST_P(BridgeModes, LoginOnly) {
  Harness h(kEncOff, kEncOff, GetParam());
  ASSERT_TRUE(h.connect()) << h.message();
  EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::LoginOnly);
  ASSERT_TRUE(h.client.handshake_done);
  ASSERT_TRUE(h.server.handshake_done);
  EXPECT_TRUE(h.bridge.tlsEstablished());

  const std::string login7 = login7Payload();
  h.client.send(kTdsLogin7, login7, /*over_tls=*/true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7, 4096));
  ASSERT_TRUE(h.bridge.login());
  EXPECT_EQ(h.bridge.login()->user_name, "app_user");
  EXPECT_EQ(h.to_server_wire.find(utf16("not-a-real-password")), std::string::npos)
      << "LOGIN7 sent in clear";

  // Plain TDS from here on, in both directions.
  h.server.send(kTdsTabularResult, loginResponse("8192"), /*over_tls=*/false);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, loginResponse("8192"), 4096));
  EXPECT_EQ(h.bridge.packetSize(), 8192u);

  h.server.received.clear();
  h.client.send(kTdsSqlBatch, "select 1", /*over_tls=*/false);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsSqlBatch, "select 1", 4096));
}

TEST_P(BridgeModes, FullReencryptsEveryType) {
  Harness h(kEncOn, kEncReq, GetParam());
  ASSERT_TRUE(h.connect()) << h.message();
  EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::Full);

  h.client.send(kTdsLogin7, login7Payload(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  h.server.send(kTdsTabularResult, loginResponse("8000"), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.packetSize(), 8000u) << "the login response is visible after decryption";

  // A batch spanning several packets and TLS records, an RPC, and types the
  // bridge does nothing special with.
  std::string expected;
  h.server.received.clear();
  for (const auto& [type, payload] : {std::pair<uint8_t, std::string>{kTdsSqlBatch,
                                                                      std::string(20000, 'B')},
                                      {kTdsRpc, "rpc"},
                                      {kTdsTransactionManager, "tm"},
                                      {0x5f, "unknown"}}) {
    h.client.send(type, payload, true, 8000);
    expected += makeTdsMessage(type, payload, 8000);
  }
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, expected);

  h.client.received.clear();
  h.server.send(kTdsTabularResult, std::string(30000, 'R'), true, 8000);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, std::string(30000, 'R'), 8000));
  EXPECT_EQ(h.to_server_wire.find(std::string(100, 'B')), std::string::npos)
      << "batch sent in clear";
}

TEST_P(BridgeModes, NoEncryption) {
  Harness h(kEncNotSup, kEncOff, GetParam());
  ASSERT_TRUE(h.connect()) << h.message();
  EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::None);
  EXPECT_FALSE(h.bridge.tlsEstablished());
  h.client.send(kTdsLogin7, login7Payload(), false);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7Payload(), 4096));
  EXPECT_TRUE(h.bridge.login());
}

TEST_P(BridgeModes, Mars) {
  Harness h(kEncOff, kEncOn, GetParam(), /*mars=*/true);
  ASSERT_TRUE(h.connect()) << h.message();
  EXPECT_TRUE(h.bridge.marsEnabled());
  h.client.send(kTdsLogin7, login7Payload(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  // An SMP SYN, then a DATA packet carrying a batch.
  const std::string smps =
      smpPacket(0x01, "") + smpPacket(0x08, makeTdsMessage(kTdsSqlBatch, "select 1", 4096));
  h.server.received.clear();
  h.client.sendRaw(smps, true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, smps);
}

TEST_P(BridgeModes, HoldsLoginUntilServerHandshakeDone) {
  Harness h(kEncOn, kEncOn, GetParam());
  h.client.start();
  h.deliver(true);  // Client PRELOGIN.
  h.deliver(false); // Server PRELOGIN response; the bridge starts both handshakes.
  // The client finishes its handshake and sends LOGIN7 while the server's
  // handshake replies are held back.
  ASSERT_TRUE(h.pump(/*hold_server=*/true)) << h.message();
  ASSERT_TRUE(h.client.handshake_done);
  ASSERT_FALSE(h.bridge.tlsEstablished());
  h.client.send(kTdsLogin7, login7Payload(), true);
  ASSERT_TRUE(h.pump(/*hold_server=*/true)) << h.message();
  EXPECT_TRUE(h.server.received.empty());

  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_TRUE(h.bridge.tlsEstablished());
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7Payload(), 4096));
}

TEST_P(BridgeModes, LoginOnlyMultiPacketLogin7WithPlainContinuation) {
  Harness h(kEncOff, kEncOff, GetParam());
  ASSERT_TRUE(h.connect()) << h.message();
  const std::string login7 = login7Payload(longLogin());
  ASSERT_GT(login7.size(), 512u - 8) << "must span packets";
  sendSplitLogin7(h.client, login7, 512);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7, 512));
  ASSERT_TRUE(h.bridge.login());
  EXPECT_EQ(h.bridge.login()->user_name, "app_user");
}

INSTANTIATE_TEST_SUITE_P(Chunks, BridgeModes, ::testing::Values(0, 1, 7, 1000));

// ---------------------------------------------------------------- PRELOGIN

TEST(Bridge, ClearsClientCertificateRequest) {
  Harness h(kEncOn | kEncClientCert, kEncOn, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  ASSERT_TRUE(h.server.peer_prelogin);
  EXPECT_FALSE(h.server.peer_prelogin->client_cert);
  EXPECT_EQ(h.server.peer_prelogin->encryption, PreloginEncryption::On);
  EXPECT_TRUE(h.bridge.clientCertCleared());
}

TEST(Bridge, PassesThroughWhenNotOpeningWithPrelogin) {
  TlsBridge bridge(contexts());
  const std::string batch = tdsPacket(kTdsSqlBatch, true, "select 1");
  BridgeOutput out;
  ASSERT_FALSE(bridge.onClientData(batch.substr(0, 3), out));
  EXPECT_TRUE(out.to_server.empty()) << "nothing sent before the first unit is known";
  ASSERT_FALSE(bridge.onClientData(batch.substr(3), out));
  EXPECT_FALSE(bridge.parsing());
  EXPECT_EQ(out.to_server, batch);
  ASSERT_FALSE(bridge.onServerData("anything", out));
  EXPECT_EQ(out.to_client, "anything");
}

// ---------------------------------------------------------------- failures

TEST(Bridge, RejectsUntrustedServerCertificate) {
  TlsSettings s = settings();
  s.upstream_ca_pem = proxyCert().cert_pem; // Not the server's issuer.
  Harness h(kEncOn, kEncOn, 0, false, contexts(s));
  h.client.start();
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Tls);
  EXPECT_NE(h.error->message.find("certificate"), std::string::npos) << h.error->message;
}

TEST(Bridge, ChecksServerName) {
  {
    Harness h(kEncOn, kEncOn, 0, false, contexts(settings("other.test")));
    h.client.start();
    h.pump();
    ASSERT_TRUE(h.error) << "name mismatch accepted";
    EXPECT_EQ(h.error->kind, BridgeError::Kind::Tls);
  }
  {
    Harness h(kEncOn, kEncOn, 0, false, contexts(settings("127.0.0.1")));
    ASSERT_TRUE(h.connect()) << h.message();
    EXPECT_TRUE(h.bridge.tlsEstablished());
  }
}

TEST(Bridge, RejectsPlainTdsAfterTlsUnderFullEncryption) {
  Harness h(kEncOn, kEncOn, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsSqlBatch, "select 1", /*over_tls=*/false);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Protocol);
}

TEST(Bridge, RejectsGarbageInsideTls) {
  Harness h(kEncOn, kEncOn, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  // Well-formed TLS around a TDS header that claims 3 bytes.
  h.client.sendRaw(std::string("\x01\x01\x00\x03\x00\x00\x01\x00", 8), true);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Protocol);
}

TEST(Bridge, RequiresLogin7First) {
  Harness h(kEncOn, kEncOn, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsSqlBatch, "select 1", true);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_NE(h.error->message.find("expected LOGIN7"), std::string::npos) << h.error->message;
}

TEST(Bridge, RejectsMalformedLogin7) {
  Harness h(kEncOn, kEncOn, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload().substr(0, 60), true);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Protocol);
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
  Harness h(kEncOff, kEncOff, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  const std::string wire = makeTdsMessage(kTdsLogin7, login7Payload(longLogin()), 512);
  h.client.sendRaw(wire.substr(0, 100), /*over_tls=*/true); // Part of the first packet.
  h.client.sendRaw(wire.substr(512), /*over_tls=*/false);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Protocol);
}

TEST(Bridge, LoginOnlyStillRejectsOtherPlainTypesDuringLogin7) {
  Harness h(kEncOff, kEncOff, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  const std::string wire = makeTdsMessage(kTdsLogin7, login7Payload(longLogin()), 512);
  h.client.sendRaw(wire.substr(0, 512), /*over_tls=*/true); // First packet, no EOM.
  h.client.send(kTdsSqlBatch, "select 1", /*over_tls=*/false);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Protocol);
}

// ---------------------------------------------------------------- local PRELOGIN

const BridgeOptions kLocal{.answer_prelogin = true};

// Login, then a query and its answer, through a bridge that answered PRELOGIN
// itself. server_tls: whether the server peer's leg encrypts its answers.
void loginAndQuery(Harness& h, bool client_login_tls, bool server_tls, bool client_plain_after) {
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_TRUE(h.to_server_wire.empty()) << "nothing goes to the server before LOGIN7";
  EXPECT_FALSE(h.bridge.upstreamStarted());

  const std::string login7 = login7Payload();
  h.client.send(kTdsLogin7, login7, client_login_tls);
  ASSERT_TRUE(h.pump()) << h.message();
  ASSERT_TRUE(h.bridge.login());
  EXPECT_TRUE(h.bridge.upstreamStarted());
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7, 4096));

  const std::string response = loginAck() + envChangePacketSize("4096", "4096") + done();
  h.server.send(kTdsTabularResult, response, server_tls);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, response, 4096));

  h.server.received.clear();
  h.client.send(kTdsSqlBatch, "select 1", !client_plain_after);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsSqlBatch, "select 1", 4096));
}

class LocalPrelogin : public ::testing::TestWithParam<size_t> {};

TEST_P(LocalPrelogin, SameModes) {
  {
    Harness h(kEncOff, kEncOff, GetParam(), false, contexts(), kLocal);
    loginAndQuery(h, true, false, true);
    EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::LoginOnly);
    EXPECT_EQ(h.bridge.serverEncryptionMode(), EncryptionMode::LoginOnly);
  }
  {
    Harness h(kEncOn, kEncOn, GetParam(), false, contexts(), kLocal);
    loginAndQuery(h, true, true, false);
    EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::Full);
    EXPECT_EQ(h.bridge.serverEncryptionMode(), EncryptionMode::Full);
  }
  {
    Harness h(kEncNotSup, kEncOff, GetParam(), false, contexts(), kLocal);
    loginAndQuery(h, false, false, true);
    EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::None);
  }
}

TEST_P(LocalPrelogin, LoginOnlyClientFullServer) {
  // The client is told encryption is off (login-only); the server forces it.
  Harness h(kEncOff, kEncReq, GetParam(), false, contexts(), kLocal);
  loginAndQuery(h, true, true, true);
  EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::LoginOnly);
  EXPECT_EQ(h.bridge.serverEncryptionMode(), EncryptionMode::Full);
}

TEST_P(LocalPrelogin, UnencryptedClientFullServer) {
  Harness h(kEncNotSup, kEncReq, GetParam(), false, contexts(), kLocal);
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.encryptionMode(), EncryptionMode::None);
  h.client.send(kTdsLogin7, login7Payload(), false);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.serverEncryptionMode(), EncryptionMode::Full);
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7Payload(), 4096));
  EXPECT_EQ(h.to_server_wire.find(utf16("not-a-real-password")), std::string::npos)
      << "LOGIN7 sent in clear on the encrypted leg";
}

TEST_P(LocalPrelogin, Mars) {
  Harness h(kEncOff, kEncOff, GetParam(), /*mars=*/true, contexts(), kLocal);
  loginAndQuery(h, true, false, true);
  EXPECT_TRUE(h.bridge.marsEnabled());
}

INSTANTIATE_TEST_SUITE_P(Chunks, LocalPrelogin, ::testing::Values(0, 1, 7, 1000));

TEST(LocalPreloginServer, RefusedMarsIsIncompatible) {
  Harness h(kEncOn, kEncOn, 0, /*mars=*/true, contexts(), kLocal, /*server_mars=*/false);
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(), true);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Incompatible);
  EXPECT_NE(h.error->message.find("MARS"), std::string::npos) << h.error->message;
}

TEST(LocalPreloginServer, UnencryptedServerIsIncompatibleWithEncryptingClient) {
  Harness h(kEncOn, kEncNotSup, 0, false, contexts(), kLocal);
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(), true);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Incompatible);
  EXPECT_TRUE(h.server.received.empty()) << "LOGIN7 must not reach the server";
}

TEST(LocalPreloginServer, PassesThroughWhenNotOpeningWithPrelogin) {
  TlsBridge bridge(contexts(), kLocal);
  const std::string batch = tdsPacket(kTdsSqlBatch, true, "select 1");
  BridgeOutput out;
  ASSERT_FALSE(bridge.onClientData(batch, out));
  EXPECT_FALSE(bridge.parsing());
  EXPECT_TRUE(bridge.upstreamStarted()) << "passthrough connects at once";
  EXPECT_EQ(out.to_server, batch);
}

// ---------------------------------------------------------------- login policy

std::shared_ptr<const AuthSettings> policy(bool ntlm_allowed, std::vector<std::string> deny) {
  return std::make_shared<const AuthSettings>(AuthSettings{.ntlm_allowed = ntlm_allowed, .deny = std::move(deny)});
}

TEST(Login, ResultFromServer) {
  Harness h(kEncOff, kEncOff, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.auth().method(), LoginMethod::Sql);
  EXPECT_EQ(h.bridge.auth().identity(), "app_user");
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Pending);
  h.server.send(kTdsTabularResult, loginResponse("4096"), false);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Succeeded);
}

TEST(Login, ServerRefusal) {
  Harness h(kEncOn, kEncOn, 0);
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  const std::string refusal = buildLoginError(18456, 1, 14, "Login failed for user 'app_user'.");
  h.server.send(kTdsTabularResult, refusal, true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, refusal, 4096));
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Failed);
  EXPECT_EQ(h.bridge.auth().serverError(), 18456u);
}

struct DenyCase {
  uint8_t client_enc;
  uint8_t server_enc;
  bool local_prelogin;
  bool login_tls; // The client sends LOGIN7 over TLS.
};

class Deny : public ::testing::TestWithParam<DenyCase> {};

TEST_P(Deny, RefusesBeforeTheServerSeesLogin7) {
  const DenyCase c = GetParam();
  Harness h(c.client_enc, c.server_enc, 7, false, contexts(),
            BridgeOptions{.answer_prelogin = c.local_prelogin, .auth = policy(true, {"APP_USER"})});
  ASSERT_TRUE(h.connect()) << h.message();
  // A LOGIN7 split into several small packets.
  h.client.send(kTdsLogin7, login7Payload(), c.login_tls, 64);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Denied) << h.message();
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Denied);
  EXPECT_TRUE(h.server.received.empty()) << "no LOGIN7 packet reaches the server";
  EXPECT_EQ(h.client.received,
            makeTdsMessage(kTdsTabularResult,
                           buildLoginError(18456, 1, 14, "Login failed for user 'app_user'."),
                           4096));
}

INSTANTIATE_TEST_SUITE_P(Modes, Deny,
                         ::testing::Values(DenyCase{kEncOff, kEncOff, false, true},
                                           DenyCase{kEncOn, kEncOn, false, true},
                                           DenyCase{kEncNotSup, kEncOff, false, false},
                                           DenyCase{kEncOn, kEncOn, true, true},
                                           DenyCase{kEncOff, kEncReq, true, true}));

// An integrated login: LOGIN7 with a Kerberos SPNEGO token, a server SSPI
// round, then the client's SSPI message, over full encryption.
TEST(Login, SspiMessagesForwardedWhole) {
  Harness h(kEncOn, kEncOn, 5, false, contexts(), BridgeOptions{.auth = policy(false, {})});
  ASSERT_TRUE(h.connect()) << h.message();
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = spnegoInit({kOidKrb5, kOidNtlm}, krb5Token(0x0100, std::string(3000, 'k')));
  f.sspi_long = true;
  h.client.send(kTdsLogin7, login7Payload(f), true, 512);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7Payload(f), 512));
  EXPECT_EQ(h.bridge.auth().method(), LoginMethod::Kerberos);

  h.server.send(kTdsTabularResult, sspiToken("server-token") + done(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Pending);

  h.server.received.clear();
  const std::string next = spnegoResp(krb5Token(0x0100, std::string(2000, 'c')));
  h.client.send(kTdsSspi, next, true, 512);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsSspi, next, 512));
}

// NTLM relayed unchanged: NEGOTIATE in LOGIN7, the server's CHALLENGE, the
// client's AUTHENTICATE, LOGINACK; the identity is read on the way.
TEST(Login, NtlmPassThrough) {
  Harness h(kEncOn, kEncOn, 3, false, contexts(), BridgeOptions{.answer_prelogin = true});
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = spnegoInit({kOidNtlm}, ntlmMessage(1));
  h.client.send(kTdsLogin7, login7Payload(f), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.auth().method(), LoginMethod::Ntlm);

  const std::string challenge = sspiToken(der(0xa1, der(0x30, der(0xa2, der(0x04, ntlmMessage(2))))));
  h.server.send(kTdsTabularResult, challenge + done(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, challenge + done(), 4096));

  h.server.received.clear();
  const std::string auth = spnegoResp(ntlmAuthenticate());
  h.client.send(kTdsSspi, auth, true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsSspi, auth, 4096)) << "relayed unchanged";
  EXPECT_EQ(h.bridge.auth().identity(), "CORP\\alice");
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Pending);

  h.server.send(kTdsTabularResult, loginResponse("4096"), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Succeeded);
}

TEST(Login, NtlmUserRefusedBeforeTheServerSeesAuthenticate) {
  Harness h(kEncOff, kEncOff, 0, false, contexts(),
            BridgeOptions{.auth = policy(true, {"CORP\\alice"})});
  ASSERT_TRUE(h.connect()) << h.message();
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = ntlmMessage(1);
  h.client.send(kTdsLogin7, login7Payload(f), true);
  ASSERT_TRUE(h.pump()) << h.message();
  h.server.send(kTdsTabularResult, sspiToken(ntlmMessage(2)) + done(), false);
  ASSERT_TRUE(h.pump()) << h.message();

  h.server.received.clear();
  h.client.send(kTdsSspi, ntlmAuthenticate(), false);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Denied);
  EXPECT_TRUE(h.server.received.empty());
  EXPECT_NE(h.client.received.find(utf16("Login failed for user 'CORP\\alice'.")),
            std::string::npos);
}

TEST(Login, NtlmRefusedWhenTheClientSwitchesToIt) {
  Harness h(kEncOff, kEncOff, 0, false, contexts(), BridgeOptions{.auth = policy(false, {})});
  ASSERT_TRUE(h.connect()) << h.message();
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = spnegoInit({kOidKrb5, kOidNtlm}, krb5Token());
  h.client.send(kTdsLogin7, login7Payload(f), true);
  ASSERT_TRUE(h.pump()) << h.message();
  h.server.send(kTdsTabularResult, sspiToken("negotiate-ntlm") + done(), false);
  ASSERT_TRUE(h.pump()) << h.message();

  h.server.received.clear();
  h.client.received.clear();
  h.client.send(kTdsSspi, spnegoResp(ntlmAuthenticate()), false);
  h.pump();
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Denied);
  EXPECT_TRUE(h.server.received.empty()) << "the NTLM message must not reach the server";
  EXPECT_EQ(h.bridge.auth().method(), LoginMethod::Ntlm);
  EXPECT_NE(h.client.received.find(utf16("Login failed")), std::string::npos);
}

// ---------------------------------------------------------------- Kerberos terminate

// Scripted stand-in for the GSS exchanges: returns the steps given, in order,
// and records what it was asked.
struct FakeKerberos : KerberosExchange {
  Step accept(std::string_view token, std::string_view binding) override {
    accepted.emplace_back(token);
    client_bindings.emplace_back(binding);
    return next(accepts);
  }
  std::string clientPrincipal() const override { return principal; }
  Step initiate(std::string_view token, const std::string& spn,
                std::string_view binding) override {
    initiated.emplace_back(token);
    spns.push_back(spn);
    server_bindings.emplace_back(binding);
    return next(initiates);
  }
  static Step next(std::vector<Step>& steps) {
    if (steps.empty()) {
      return Step{.error = "no step scripted"};
    }
    Step s = steps.front();
    steps.erase(steps.begin());
    return s;
  }

  std::vector<Step> accepts;
  std::vector<Step> initiates;
  std::string principal = "alice@TEST.REALM";
  std::vector<std::string> accepted, initiated, spns, client_bindings, server_bindings;
};

struct FakeTerminator : KerberosTerminator {
  std::shared_ptr<KerberosExchange> start() const override { return exchange; }
  std::shared_ptr<FakeKerberos> exchange = std::make_shared<FakeKerberos>();
};

struct Terminate {
  std::shared_ptr<FakeTerminator> terminator = std::make_shared<FakeTerminator>();
  FakeKerberos& gss = *terminator->exchange;

  std::shared_ptr<const AuthSettings> settings(std::vector<std::string> deny = {},
                                               ChannelBinding binding = ChannelBinding::None) {
    AuthSettings s{.deny = std::move(deny)};
    s.terminate = KerberosTerminate{.terminator = terminator,
                                    .spn = "MSSQLSvc/sql.test:1433",
                                    .channel_binding = binding};
    return std::make_shared<const AuthSettings>(std::move(s));
  }
};

Login7Fields kerberosLogin() {
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = spnegoInit({kOidMsKrb5, kOidKrb5}, krb5Token(0x0100, "client-ap-req"));
  f.feature_ext = std::string("\x0a\x01\x00\x00\x00\x01\xff", 7);
  return f;
}

// The client's LOGIN7 as the server must get it: the proxy's token in place.
std::string upstreamLogin(std::string token) {
  Login7Fields f = kerberosLogin();
  f.sspi = std::move(token);
  return makeTdsMessage(kTdsLogin7, login7Payload(f), 4096);
}

struct TerminateCase {
  uint8_t client_enc;
  uint8_t server_enc;
  bool local_prelogin;
  bool login_tls;  // The client sends LOGIN7 over TLS.
  bool server_tls; // The server answers over TLS (full encryption).
};

class TerminateModes : public ::testing::TestWithParam<TerminateCase> {};

// The whole exchange: the proxy accepts the client, logs in to the server
// with its own token, checks the server's answer, and hands the client its
// own answer with LOGINACK.
TEST_P(TerminateModes, LogsInWithTheProxysOwnToken) {
  const TerminateCase c = GetParam();
  Terminate t;
  t.gss.accepts = {{.token = "proxy-ap-rep", .complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}, {.complete = true}};
  Harness h(c.client_enc, c.server_enc, 7, false, contexts(),
            BridgeOptions{.answer_prelogin = c.local_prelogin, .auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  const Login7Fields f = kerberosLogin();
  h.client.send(kTdsLogin7, login7Payload(f), c.login_tls, 512);
  ASSERT_TRUE(h.pump()) << h.message();
  ASSERT_EQ(t.gss.accepted, std::vector<std::string>{f.sspi});
  EXPECT_EQ(h.bridge.auth().identity(), "alice@TEST.REALM");
  EXPECT_EQ(h.bridge.auth().method(), LoginMethod::Kerberos);
  EXPECT_EQ(t.gss.spns, std::vector<std::string>{"MSSQLSvc/sql.test:1433"});
  EXPECT_EQ(h.server.received, upstreamLogin("proxy-to-server"))
      << "everything but the token as the client sent it";
  EXPECT_TRUE(h.client.received.empty());

  h.server.send(kTdsTabularResult, sspiToken("server-ap-rep") + loginResponse("4096"),
                c.server_tls);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(t.gss.initiated.back(), "server-ap-rep");
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult,
                                              sspiToken("proxy-ap-rep") + loginResponse("4096"),
                                              4096));
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Succeeded);
  EXPECT_EQ(h.steps_run, 3u);

  // Then the session carries on as usual.
  h.server.received.clear();
  h.client.send(kTdsSqlBatch, "select 1", c.client_enc == kEncOn);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsSqlBatch, "select 1", 4096));
}

INSTANTIATE_TEST_SUITE_P(Modes, TerminateModes,
                         ::testing::Values(TerminateCase{kEncOff, kEncOff, false, true, false},
                                           TerminateCase{kEncOn, kEncOn, false, true, true},
                                           TerminateCase{kEncNotSup, kEncOff, false, false, false},
                                           TerminateCase{kEncOn, kEncOn, true, true, true},
                                           TerminateCase{kEncNotSup, kEncOff, true, false, false},
                                           TerminateCase{kEncOff, kEncReq, true, true, true}));

TEST(Terminate, RoundsWithTheClientStayLocal) {
  Terminate t;
  t.gss.accepts = {{.token = "acceptor-round"}, {.token = "proxy-final", .complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}, {.complete = true}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.answer_prelogin = true, .auth = t.settings()});
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received,
            makeTdsMessage(kTdsTabularResult, sspiToken("acceptor-round"), 4096));
  EXPECT_TRUE(h.to_server_wire.empty()) << "the server isn't contacted before the client is in";
  EXPECT_FALSE(h.bridge.upstreamStarted());

  h.client.received.clear();
  h.client.send(kTdsSspi, "client-round", true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(t.gss.accepted.back(), "client-round");
  EXPECT_TRUE(h.bridge.upstreamStarted());
  EXPECT_EQ(h.server.received, upstreamLogin("proxy-to-server"));

  h.server.send(kTdsTabularResult, sspiToken("server-ap-rep") + loginResponse("4096"), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult,
                                              sspiToken("proxy-final") + loginResponse("4096"),
                                              4096));
}

TEST(Terminate, RoundsWithTheServerStayLocal) {
  Terminate t;
  t.gss.accepts = {{.complete = true}}; // No final token for the client.
  t.gss.initiates = {{.token = "proxy-1"}, {.token = "proxy-2"}, {.complete = true}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(h.pump()) << h.message();

  h.server.received.clear();
  h.server.send(kTdsTabularResult, sspiToken("server-round"), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsSspi, "proxy-2", 4096));
  EXPECT_TRUE(h.client.received.empty()) << "the server's round is the proxy's business";

  h.server.send(kTdsTabularResult, sspiToken("server-final") + loginResponse("4096"), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(t.gss.initiated, (std::vector<std::string>{"", "server-round", "server-final"}));
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, loginResponse("4096"), 4096));
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Succeeded);
}

// Expects the login refused: ERROR 18456 to the client, and no LOGIN7 at the
// server unless sent is set.
void expectRefused(Harness& h, std::string_view reason, bool sent = false) {
  ASSERT_TRUE(h.error);
  EXPECT_EQ(h.error->kind, BridgeError::Kind::Denied) << h.message();
  EXPECT_NE(h.message().find(reason), std::string::npos) << h.message();
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Denied);
  EXPECT_NE(h.client.received.find(utf16("Login failed for user '")), std::string::npos);
  if (!sent) {
    EXPECT_TRUE(h.server.received.empty()) << "no LOGIN7 reaches the server";
  }
}

TEST(Terminate, ClientTheProxyCantAcceptIsRefused) {
  Terminate t;
  t.gss.accepts = {{.error = "Decrypt integrity check failed"}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  h.pump();
  expectRefused(h, "Decrypt integrity check failed");
  EXPECT_TRUE(t.gss.initiated.empty());
}

TEST(Terminate, DenyListAppliesToTheAcceptedPrincipal) {
  Terminate t;
  t.gss.accepts = {{.complete = true}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.answer_prelogin = true, .auth = t.settings({"ALICE@test.realm"})});
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  h.pump();
  expectRefused(h, "deny list");
  EXPECT_TRUE(h.to_server_wire.empty()) << "the server is never contacted";
  EXPECT_NE(h.client.received.find(utf16("Login failed for user 'alice@TEST.REALM'.")),
            std::string::npos);
}

TEST(Terminate, ServerTicketFailureIsRefused) {
  Terminate t;
  t.gss.accepts = {{.complete = true}};
  t.gss.initiates = {{.error = "Server not found in Kerberos database"}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  h.pump();
  expectRefused(h, "Server not found in Kerberos database");
}

TEST(Terminate, ServerThatDoesntAuthenticateItselfIsRefused) {
  Terminate t;
  t.gss.accepts = {{.token = "proxy-ap-rep", .complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(h.pump()) << h.message();
  h.server.send(kTdsTabularResult, loginResponse("4096"), true); // LOGINACK, no AP-REP.
  h.pump();
  expectRefused(h, "without authenticating itself", /*sent=*/true);
  EXPECT_EQ(h.client.received.find(loginAck()), std::string::npos) << "LOGINACK held back";
}

TEST(Terminate, ServerRefusalReachesTheClient) {
  Terminate t;
  t.gss.accepts = {{.token = "proxy-ap-rep", .complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(h.pump()) << h.message();
  const std::string refusal = buildLoginError(18456, 1, 14, "Login failed for user ''.");
  h.server.send(kTdsTabularResult, refusal, true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.client.received, makeTdsMessage(kTdsTabularResult, refusal, 4096));
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Failed);
  EXPECT_EQ(h.bridge.auth().identity(), "alice@TEST.REALM");
}

TEST(Terminate, NtlmPassesThrough) {
  Terminate t;
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = spnegoInit({kOidNtlm}, ntlmMessage(1));
  h.client.send(kTdsLogin7, login7Payload(f), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7Payload(f), 4096));
  EXPECT_EQ(h.steps_run, 0u);
}

TEST(Terminate, SqlLoginsPassThrough) {
  Terminate t;
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7Payload(), 4096));
  EXPECT_EQ(h.steps_run, 0u);
}

TEST(Terminate, UsesTheSpnItIsGiven) {
  Terminate t;
  t.gss.accepts = {{.complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.answer_prelogin = true, .auth = t.settings()});
  h.client.start();
  ASSERT_TRUE(h.pump()) << h.message();
  h.bridge.setUpstreamSpn("MSSQLSvc/b.test:1433"); // As the filter does when routing.
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(t.gss.spns, std::vector<std::string>{"MSSQLSvc/b.test:1433"});
}

std::string endPoint(const std::string& cert_pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())));
  bssl::UniquePtr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  uint8_t hash[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EXPECT_TRUE(X509_digest(cert.get(), EVP_sha256(), hash, &len)); // ECDSA with SHA-256.
  return "tls-server-end-point:" + std::string(reinterpret_cast<char*>(hash), len);
}

TEST(Terminate, ChannelBindingOfEachLegsCertificate) {
  Terminate t;
  t.gss.accepts = {{.complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}};
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.auth = t.settings({}, ChannelBinding::TlsServerEndPoint)});
  ASSERT_TRUE(h.connect()) << h.message();
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(t.gss.client_bindings, std::vector<std::string>{endPoint(proxyCert().cert_pem)});
  EXPECT_EQ(t.gss.server_bindings, std::vector<std::string>{endPoint(serverCert().cert_pem)});

  // No TLS on a leg: nothing to bind to.
  Terminate plain;
  plain.gss.accepts = {{.complete = true}};
  plain.gss.initiates = {{.token = "proxy-to-server"}};
  Harness p(kEncNotSup, kEncOff, 0, false, contexts(),
            BridgeOptions{.auth = plain.settings({}, ChannelBinding::TlsServerEndPoint)});
  ASSERT_TRUE(p.connect()) << p.message();
  p.client.send(kTdsLogin7, login7Payload(kerberosLogin()), false);
  ASSERT_TRUE(p.pump()) << p.message();
  EXPECT_EQ(plain.gss.client_bindings, std::vector<std::string>{""});
  EXPECT_EQ(plain.gss.server_bindings, std::vector<std::string>{""});

  // Off by default.
  Terminate none;
  none.gss.accepts = {{.complete = true}};
  none.gss.initiates = {{.token = "proxy-to-server"}};
  Harness n(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = none.settings()});
  ASSERT_TRUE(n.connect()) << n.message();
  n.client.send(kTdsLogin7, login7Payload(kerberosLogin()), true);
  ASSERT_TRUE(n.pump()) << n.message();
  EXPECT_EQ(none.gss.client_bindings, std::vector<std::string>{""});
}

TEST(Terminate, HoldsDataWhileAStepRuns) {
  Terminate t;
  t.gss.accepts = {{.complete = true}};
  t.gss.initiates = {{.token = "proxy-to-server"}};
  Harness h(kEncNotSup, kEncOff, 0, false, contexts(), BridgeOptions{.auth = t.settings()});
  ASSERT_TRUE(h.connect()) << h.message();
  h.hold_work = true;
  h.client.send(kTdsLogin7, login7Payload(kerberosLogin()), false);
  ASSERT_TRUE(h.pump()) << h.message();
  ASSERT_TRUE(h.bridge.waiting());
  // A client that doesn't wait for its answer: held, then refused.
  h.client.send(kTdsSqlBatch, "select 1", false);
  ASSERT_TRUE(h.pump()) << "held, not processed yet: " << h.message();
  h.hold_work = false;
  h.runWork(); // Accepts, then initiates; only then is the held data read.
  EXPECT_EQ(h.steps_run, 2u);
  ASSERT_TRUE(h.error);
  EXPECT_NE(h.message().find("client data during the proxy's Kerberos login"), std::string::npos)
      << h.message();
}

TEST(Terminate, ResumeWithoutAStepFails) {
  Terminate t;
  TlsBridge bridge(contexts(), BridgeOptions{.auth = t.settings()});
  BridgeOutput out;
  EXPECT_TRUE(bridge.resume(out));
}

} // namespace
} // namespace MssqlProxy
