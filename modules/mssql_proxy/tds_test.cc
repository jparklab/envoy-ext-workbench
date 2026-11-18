#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "login7.h"
#include "tds.h"
#include "tds_connection.h"
#include "test_util.h"

namespace MssqlProxy {
namespace {

using namespace test;

// ---------------------------------------------------------------- splitter

TEST(StreamSplitter, WholePacket) {
  StreamSplitter s;
  Collect c;
  const std::string p = tdsPacket(kTdsSqlBatch, true, "select 1");
  ASSERT_FALSE(s.feed(p, c));
  ASSERT_EQ(c.units.size(), 1u);
  EXPECT_EQ(c.units[0].kind, UnitKind::TdsPacket);
  EXPECT_EQ(c.units[0].type, kTdsSqlBatch);
  EXPECT_TRUE(c.units[0].eom);
  EXPECT_EQ(c.bytes[0], p);
  EXPECT_EQ(s.bufferedBytes(), 0u);
}

TEST(StreamSplitter, SplitAtEveryByte) {
  const std::string p = tdsPacket(kTdsSqlBatch, true, "select 1");
  for (size_t cut = 1; cut < p.size(); ++cut) {
    StreamSplitter s;
    Collect c;
    ASSERT_FALSE(s.feed(p.substr(0, cut), c));
    EXPECT_TRUE(c.units.empty()) << "cut " << cut;
    ASSERT_FALSE(s.feed(p.substr(cut), c));
    ASSERT_EQ(c.units.size(), 1u) << "cut " << cut;
    EXPECT_EQ(c.bytes[0], p);
  }
}

TEST(StreamSplitter, SeveralUnitsInOneRead) {
  StreamSplitter s;
  Collect c;
  const std::string a = tdsPacket(kTdsSqlBatch, false, "part one ");
  const std::string b = tdsPacket(kTdsSqlBatch, true, "part two");
  const std::string r = tlsRecord(0x17, "ciphertext");
  ASSERT_FALSE(s.feed(a + b + r + a.substr(0, 3), c));
  ASSERT_EQ(c.units.size(), 3u);
  EXPECT_FALSE(c.units[0].eom);
  EXPECT_TRUE(c.units[1].eom);
  EXPECT_EQ(c.units[2].kind, UnitKind::TlsRecord);
  EXPECT_EQ(c.bytes[2], r);
  EXPECT_EQ(s.bufferedBytes(), 3u);
}

TEST(StreamSplitter, RejectsBadTdsLength) {
  for (size_t len : {0, 7, 32768, 65535}) {
    StreamSplitter s;
    Collect c;
    std::string p = tdsPacket(kTdsSqlBatch, true, "");
    p[2] = static_cast<char>(len >> 8);
    p[3] = static_cast<char>(len & 0xff);
    EXPECT_TRUE(s.feed(p, c)) << "length " << len;
    EXPECT_TRUE(s.feed("more", c)) << "stays failed";
  }
}

TEST(StreamSplitter, RejectsBadTlsRecord) {
  {
    StreamSplitter s;
    Collect c;
    EXPECT_TRUE(s.feed(std::string("\x17\x03\x03\x00\x00", 5), c)) << "empty record";
  }
  {
    StreamSplitter s;
    Collect c;
    EXPECT_TRUE(s.feed(std::string("\x17\x03\x03\x48\x01", 5), c)) << "too long";
  }
  {
    StreamSplitter s;
    Collect c;
    EXPECT_TRUE(s.feed(std::string("\x16\x02\x00\x00\x01", 5), c)) << "bad version";
  }
}

TEST(StreamSplitter, SmpOnlyWithMars) {
  std::string smp(16, '\0');
  smp[0] = static_cast<char>(kSmpId);
  smp[1] = 0x08; // DATA
  smp[4] = 20;   // length 20, little endian
  smp += "data";
  {
    StreamSplitter s;
    s.setMarsEnabled(true);
    Collect c;
    ASSERT_FALSE(s.feed(smp, c));
    ASSERT_EQ(c.units.size(), 1u);
    EXPECT_EQ(c.units[0].kind, UnitKind::SmpPacket);
    EXPECT_EQ(c.units[0].payload(), "data");
  }
  {
    // Without MARS, 0x53 is read as a TDS packet; this header's length is 0.
    StreamSplitter s;
    Collect c;
    EXPECT_TRUE(s.feed(smp, c));
  }
}

// ---------------------------------------------------------------- PRELOGIN

TEST(Prelogin, ParsesEncryptionAndMars) {
  std::string error;
  auto o = parsePrelogin(preloginPayload(0x01, 1), error);
  ASSERT_TRUE(o) << error;
  EXPECT_EQ(o->encryption, PreloginEncryption::On);
  EXPECT_EQ(o->mars, true);

  o = parsePrelogin(preloginPayload(0x80), error); // Client-cert bit + OFF.
  ASSERT_TRUE(o) << error;
  EXPECT_EQ(o->encryption, PreloginEncryption::Off);
  EXPECT_FALSE(o->mars);
}

TEST(Prelogin, RejectsMalformed) {
  std::string error;
  const std::string good = preloginPayload(0x00);

  EXPECT_FALSE(parsePrelogin("", error));
  EXPECT_FALSE(parsePrelogin(good.substr(0, 3), error)) << "entry truncated";
  EXPECT_FALSE(parsePrelogin(good.substr(0, 10), error)) << "no terminator";

  std::string bad = good;
  bad[1] = 0x7f; // VERSION offset far past the end.
  EXPECT_FALSE(parsePrelogin(bad, error));

  bad = good;
  bad[9] = 2; // ENCRYPTION length 2.
  EXPECT_FALSE(parsePrelogin(bad, error));

  EXPECT_FALSE(parsePrelogin(preloginPayload(0x05), error)) << "unknown value";
}

TEST(Prelogin, ReportsClientCertBitAndEncryptionOffset) {
  const std::string payload = preloginPayload(0x81);
  std::string error;
  auto options = parsePrelogin(payload, error);
  ASSERT_TRUE(options) << error;
  EXPECT_EQ(options->encryption, PreloginEncryption::On);
  EXPECT_TRUE(options->client_cert);
  ASSERT_TRUE(options->encryption_offset);
  EXPECT_EQ(static_cast<uint8_t>(payload[*options->encryption_offset]), 0x81);
}

TEST(MakeTdsMessage, SplitsIntoPackets) {
  const std::string payload(10, 'p');
  const std::string message = makeTdsMessage(kTdsPrelogin, payload, kTdsHeaderSize + 4);
  StreamSplitter s;
  Collect c;
  ASSERT_FALSE(s.feed(message, c));
  ASSERT_EQ(c.units.size(), 3u);
  std::string joined;
  for (size_t i = 0; i < c.bytes.size(); ++i) {
    EXPECT_EQ(static_cast<uint8_t>(c.bytes[i][0]), kTdsPrelogin);
    EXPECT_EQ(c.bytes[i][1] == kTdsStatusEom, i == 2) << "EOM on the last packet only";
    EXPECT_EQ(static_cast<uint8_t>(c.bytes[i][6]), i + 1) << "packet ID";
    joined += c.bytes[i].substr(kTdsHeaderSize);
  }
  EXPECT_EQ(joined, payload);
  EXPECT_EQ(makeTdsMessage(kTdsSqlBatch, "", 4096), tdsPacket(kTdsSqlBatch, true, ""))
      << "an empty payload is one empty packet";
}

TEST(Prelogin, BuildsResponseMatchingTheRequest) {
  std::string error;
  auto client = parsePrelogin(preloginPayload(0x01, /*mars=*/1), error);
  ASSERT_TRUE(client) << error;
  const std::string response =
      buildPreloginResponse(*client, PreloginEncryption::On, std::string(6, '\x10'));
  auto parsed = parsePrelogin(response, error);
  ASSERT_TRUE(parsed) << error;
  EXPECT_EQ(parsed->encryption, PreloginEncryption::On);
  EXPECT_EQ(parsed->mars, true);
  EXPECT_FALSE(parsed->instance) << "the client sent no INSTOPT";
  EXPECT_FALSE(parsed->nonce);
}

// ---------------------------------------------------------------- LOGIN7

TEST(Login7, ParsesFields) {
  Login7Fields f;
  f.database = "Sales";
  f.integrated = true;
  std::string error;
  auto login = parseLogin7(login7Payload(f), error);
  ASSERT_TRUE(login) << error;
  EXPECT_EQ(login->user_name, "app_user");
  EXPECT_EQ(login->database, "Sales");
  EXPECT_EQ(login->server_name, "db.test");
  EXPECT_EQ(login->app_name, "test-app");
  EXPECT_EQ(login->host_name, "client-host");
  EXPECT_EQ(login->library_name, "ODBC");
  EXPECT_EQ(login->tds_version, 0x74000004u);
  EXPECT_EQ(login->packet_size, 4096u);
  EXPECT_TRUE(login->integrated);
  EXPECT_FALSE(login->has_sspi);
}

TEST(Login7, RejectsMalformed) {
  std::string error;
  const std::string good = login7Payload();
  EXPECT_FALSE(parseLogin7(good.substr(0, 50), error)) << "shorter than the fixed part";

  std::string bad = good;
  bad[0] = static_cast<char>(0xff); // Length beyond the message.
  bad[1] = static_cast<char>(0xff);
  EXPECT_FALSE(parseLogin7(bad, error));

  bad = good;
  bad[68] = static_cast<char>(0xf0); // Database offset beyond the end.
  bad[69] = static_cast<char>(0xff);
  EXPECT_FALSE(parseLogin7(bad, error));
  EXPECT_NE(error.find("database"), std::string::npos) << error;

  bad = good;
  bad[42] = static_cast<char>(200); // User name longer than 128 characters.
  EXPECT_FALSE(parseLogin7(bad, error));
}

TEST(Login7, ConvertsUtf16) {
  // "é", "€", U+1F600 as a surrogate pair, and an unpaired surrogate.
  const std::string utf16le("\xe9\x00\xac\x20\x3d\xd8\x00\xde\x00\xd8", 10);
  EXPECT_EQ(utf16leToUtf8(utf16le), "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\xef\xbf\xbd");
}

// ---------------------------------------------------------------- login response

TEST(LoginResponse, FindsPacketSizeAndLoginAck) {
  std::string error;
  auto scan = scanLoginResponse(loginAck() + envChangePacketSize("8192", "4096") + done(), error);
  ASSERT_TRUE(scan) << error;
  EXPECT_TRUE(scan->login_ack);
  EXPECT_EQ(scan->packet_size, 8192u);
  EXPECT_TRUE(scan->fully_scanned);
}

TEST(LoginResponse, StopsAtUnknownToken) {
  std::string error;
  auto scan = scanLoginResponse(envChangePacketSize("1024", "4096") + "\x81" + "rest", error);
  ASSERT_TRUE(scan) << error;
  EXPECT_EQ(scan->packet_size, 1024u);
  EXPECT_FALSE(scan->fully_scanned);
}

TEST(LoginResponse, RejectsMalformed) {
  std::string error;
  EXPECT_FALSE(scanLoginResponse(loginAck().substr(0, 5), error)) << "truncated token";
  EXPECT_FALSE(scanLoginResponse(envChangePacketSize("40x6", "4096"), error)) << "not a number";
  EXPECT_FALSE(scanLoginResponse(envChangePacketSize("100", "4096"), error)) << "below 512";
  EXPECT_FALSE(scanLoginResponse(envChangePacketSize("40000", "4096"), error)) << "above 32767";
  EXPECT_FALSE(scanLoginResponse(done().substr(0, 6), error)) << "short DONE";
}

// ---------------------------------------------------------------- tracker

std::string clientPrelogin(uint8_t enc, std::optional<uint8_t> mars = std::nullopt) {
  return tdsPacket(kTdsPrelogin, true, preloginPayload(enc, mars));
}
std::string serverPrelogin(uint8_t enc, std::optional<uint8_t> mars = std::nullopt) {
  return tdsPacket(kTdsTabularResult, true, preloginPayload(enc, mars));
}

TEST(ConnectionTracker, NoEncryption) {
  ConnectionTracker t;
  ASSERT_FALSE(t.onClientData(clientPrelogin(0x02)));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x02)));
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::None);
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "login")));
  ASSERT_FALSE(t.onServerData(tdsPacket(kTdsTabularResult, true, "loginack")));
  EXPECT_TRUE(t.onClientData(tlsRecord(0x17, "x"))) << "no TLS when none negotiated";
}

TEST(ConnectionTracker, EnforcesNegotiatedPacketSize) {
  ConnectionTracker t;
  ASSERT_FALSE(t.onClientData(clientPrelogin(0x02)));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x02)));
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "login")));
  // The login response arrives in two packets; the size applies once it ends.
  const std::string response = loginAck() + envChangePacketSize("512", "4096") + done();
  ASSERT_FALSE(t.onServerData(tdsPacket(kTdsTabularResult, false, response.substr(0, 9))));
  EXPECT_FALSE(t.packetSize());
  ASSERT_FALSE(t.onServerData(tdsPacket(kTdsTabularResult, true, response.substr(9))));
  EXPECT_EQ(t.packetSize(), 512u);

  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsSqlBatch, true, std::string(512 - 8, 'a'))));
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsSqlBatch, true, std::string(512 - 7, 'a'))));
}

TEST(ConnectionTracker, PreloginSplitAcrossPackets) {
  ConnectionTracker t;
  const std::string payload = preloginPayload(0x00);
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsPrelogin, false, payload.substr(0, 4))));
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsPrelogin, true, payload.substr(4))));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x00)));
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::LoginOnly);
}

TEST(ConnectionTracker, FullEncryptionRejectsPlainAfterTls) {
  ConnectionTracker t;
  ASSERT_FALSE(t.onClientData(clientPrelogin(0x01)));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x01)));
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsPrelogin, true, "\x16\x03\x01 hello")));
  ASSERT_FALSE(t.onServerData(tdsPacket(kTdsPrelogin, true, "\x16\x03\x03 hello")));
  ASSERT_FALSE(t.onClientData(tlsRecord(0x17, "login7")));
  ASSERT_FALSE(t.onServerData(tlsRecord(0x17, "loginack")));
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::Full);
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsSqlBatch, true, "select 1")));
}

TEST(ConnectionTracker, RejectsPlainLoginWhenEncrypting) {
  ConnectionTracker t;
  ASSERT_FALSE(t.onClientData(clientPrelogin(0x00)));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x00)));
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsLogin7, true, "plaintext login")));
}

// Login-only, both handshakes done, and the first LOGIN7 packet sent over TLS.
void startLoginOnlyLogin(ConnectionTracker& t) {
  ASSERT_FALSE(t.onClientData(clientPrelogin(0x00)));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x00)));
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsPrelogin, true, "\x16\x03\x01 hello")));
  ASSERT_FALSE(t.onServerData(tdsPacket(kTdsPrelogin, true, "\x16\x03\x03 hello")));
  ASSERT_FALSE(t.onClientData(tlsRecord(0x17, "login7 first packet")));
  ASSERT_EQ(t.encryptionMode(), EncryptionMode::LoginOnly);
}

TEST(ConnectionTracker, LoginOnlyAcceptsPlainLogin7ContinuationAfterTls) {
  // mssql-jdbc encrypts only the first packet of a long (Kerberos) LOGIN7, as
  // MS-TDS requires under login-only encryption.
  ConnectionTracker t;
  startLoginOnlyLogin(t);
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, false, "second")));
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "third")));
  EXPECT_FALSE(t.onServerData(tdsPacket(kTdsTabularResult, true, loginAck() + done())));
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsSqlBatch, true, "select 1")));
}

TEST(ConnectionTracker, LoginOnlyStillRejectsOtherPlainTypesAfterTls) {
  ConnectionTracker t;
  startLoginOnlyLogin(t);
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsSqlBatch, true, "select 1")));
}

TEST(ConnectionTracker, LoginOnlyRejectsPlainLogin7AfterItsEnd) {
  ConnectionTracker t;
  startLoginOnlyLogin(t);
  ASSERT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "last")));
  EXPECT_TRUE(t.onClientData(tdsPacket(kTdsLogin7, true, "another")));
}

TEST(ConnectionTracker, RejectsOutOfOrder) {
  {
    ConnectionTracker t;
    EXPECT_TRUE(t.onServerData(serverPrelogin(0x00))) << "server speaks first";
  }
  {
    ConnectionTracker t;
    ASSERT_FALSE(t.onClientData(clientPrelogin(0x00)));
    EXPECT_TRUE(t.onClientData(clientPrelogin(0x00))) << "client before the response";
  }
}

TEST(ConnectionTracker, PassiveWhenNotOpeningWithPrelogin) {
  ConnectionTracker t;
  EXPECT_FALSE(t.onClientData(tdsPacket(kTdsLogin7, true, "old client")));
  EXPECT_FALSE(t.parsing());
  EXPECT_FALSE(t.onServerData("anything at all"));
}

TEST(ConnectionTracker, MarsEnablesSmp) {
  ConnectionTracker t;
  ASSERT_FALSE(t.onClientData(clientPrelogin(0x02, 1)));
  ASSERT_FALSE(t.onServerData(serverPrelogin(0x02, 1)));
  EXPECT_TRUE(t.marsEnabled());
  std::string smp(16, '\0');
  smp[0] = static_cast<char>(kSmpId);
  smp[1] = 0x01; // SYN
  smp[4] = 16;
  ASSERT_FALSE(t.onClientData(smp));
  EXPECT_EQ(t.stats(Direction::ClientToServer).smp_packets, 1u);
}

// ---------------------------------------------------------------- fixtures

struct Event {
  Direction direction;
  std::string bytes;
};

std::vector<Event> loadFixture(const std::string& name) {
  // FIXTURES holds the fixtures' runfiles paths, set by the BUILD file.
  const char* srcdir = std::getenv("TEST_SRCDIR");
  const char* list = std::getenv("FIXTURES");
  if (srcdir == nullptr || list == nullptr) {
    ADD_FAILURE() << "TEST_SRCDIR or FIXTURES not set";
    return {};
  }
  std::istringstream paths(list);
  std::string path;
  while (paths >> path) {
    if (path.ends_with("/" + name + ".tds")) {
      break;
    }
    path.clear();
  }
  if (path.empty()) {
    ADD_FAILURE() << "fixture " << name << " not in FIXTURES";
    return {};
  }
  std::ifstream in(std::string(srcdir) + "/" + path);
  std::vector<Event> events;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::string bytes;
    for (size_t i = 2; i + 1 < line.size(); i += 2) {
      bytes.push_back(static_cast<char>(std::stoi(line.substr(i, 2), nullptr, 16)));
    }
    events.push_back({line[0] == 'C' ? Direction::ClientToServer : Direction::ServerToClient,
                      std::move(bytes)});
  }
  EXPECT_FALSE(events.empty()) << name;
  return events;
}

// Replays a fixture, feeding each event in chunks of `chunk` bytes

TEST(Login7, ReadsSspi) {
  std::string error;
  Login7Fields f;
  f.integrated = true;
  f.sspi = "token";
  auto login = parseLogin7(login7Payload(f), error);
  ASSERT_TRUE(login) << error;
  EXPECT_TRUE(login->has_sspi);
  EXPECT_EQ(login->sspi, "token");

  f.sspi = std::string(70000, 's'); // Beyond cbSSPI's 16 bits.
  f.sspi_long = true;
  login = parseLogin7(login7Payload(f), error);
  ASSERT_TRUE(login) << error;
  EXPECT_EQ(login->sspi.size(), 70000u);

  std::string bad = login7Payload(f);
  bad[90] = static_cast<char>(0xff); // cbSSPILong past the end.
  bad[91] = static_cast<char>(0xff);
  EXPECT_FALSE(parseLogin7(bad, error));
}

// A FEATUREEXT block: one feature (id, DWORD length, data), then 0xFF.
const std::string kFeatureExt{"\x0a\x01\x00\x00\x00\x01\xff", 7};

TEST(Login7, ReplacesSspi) {
  std::string error;
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = "client-token";
  f.feature_ext = kFeatureExt; // After the SSPI data, so its pointer moves.
  const std::string original = login7Payload(f);

  // The result is what the client would have sent with the other token.
  for (std::string token : {std::string("a-longer-token-from-the-proxy"), std::string("p"),
                            std::string(70000, 'p')}) {
    auto replaced = replaceLogin7Sspi(original, token, error);
    ASSERT_TRUE(replaced) << error;
    Login7Fields want = f;
    want.sspi = token;
    want.sspi_long = token.size() >= 0xffff;
    EXPECT_EQ(*replaced, login7Payload(want)) << token.size();
    auto login = parseLogin7(*replaced, error);
    ASSERT_TRUE(login) << error;
    EXPECT_EQ(login->sspi, token);
    EXPECT_EQ(login->database, "master");
  }
  // From cbSSPILong back to cbSSPI.
  Login7Fields long_sspi = f;
  long_sspi.sspi = std::string(70000, 'c');
  long_sspi.sspi_long = true;
  auto replaced = replaceLogin7Sspi(login7Payload(long_sspi), "client-token", error);
  ASSERT_TRUE(replaced) << error;
  EXPECT_EQ(*replaced, original);
}

TEST(Login7, RefusesSspiReplacementThatCantFit) {
  std::string error;
  Login7Fields f;
  f.integrated = true;
  f.sspi = "client-token";
  f.tds_version = 0x71000001; // TDS 7.1: no cbSSPILong.
  EXPECT_FALSE(replaceLogin7Sspi(login7Payload(f), std::string(70000, 'p'), error));
  EXPECT_NE(error.find("7.1"), std::string::npos) << error;

  f.tds_version = 0x74000004;
  std::string overlapping = login7Payload(f);
  overlapping[36] = overlapping[78]; // The host name starts inside the SSPI data.
  overlapping[37] = overlapping[79];
  overlapping[38] = 1;
  EXPECT_FALSE(replaceLogin7Sspi(overlapping, "p", error));
  EXPECT_NE(error.find("overlaps"), std::string::npos) << error;
  EXPECT_FALSE(replaceLogin7Sspi("short", "p", error));
}

TEST(LoginResponse, ReplacesSspiTokens) {
  std::string error;
  const std::string rest = loginAck() + done();
  const std::string one = sspiToken("server") + rest;
  auto scan = scanLoginResponse(one, error);
  ASSERT_TRUE(scan) << error;
  ASSERT_EQ(scan->sspi_tokens.size(), 1u);
  EXPECT_EQ(replaceSspiTokens(one, *scan, "proxy"), sspiToken("proxy") + rest);
  EXPECT_EQ(replaceSspiTokens(one, *scan, ""), rest);

  const std::string two = loginAck() + sspiToken("a") + sspiToken("b") + done();
  scan = scanLoginResponse(two, error);
  ASSERT_TRUE(scan) << error;
  EXPECT_EQ(scan->sspi_tokens.size(), 2u);
  EXPECT_EQ(replaceSspiTokens(two, *scan, "proxy"), loginAck() + sspiToken("proxy") + done());

  scan = scanLoginResponse(rest, error);
  ASSERT_TRUE(scan) << error;
  EXPECT_EQ(replaceSspiTokens(rest, *scan, "proxy"), sspiToken("proxy") + rest);
  EXPECT_EQ(replaceSspiTokens(rest, *scan, ""), rest);
}

TEST(Message, KeepsTheServersSpid) {
  const std::string message = makeTdsMessage(kTdsTabularResult, "x", 4096, 0x1234);
  EXPECT_EQ(message.substr(4, 2), std::string("\x12\x34", 2));
  EXPECT_EQ(makeTdsMessage(kTdsTabularResult, "x", 4096).substr(4, 2), std::string(2, '\0'));
}

TEST(LoginResponse, SspiAndError) {
  std::string error;
  const std::string sspi = std::string(1, static_cast<char>(0xed)) + le16(3) + "tok";
  auto scan = scanLoginResponse(sspi + done(), error);
  ASSERT_TRUE(scan) << error;
  EXPECT_EQ(scan->sspi, "tok");
  EXPECT_FALSE(scan->login_ack);

  scan = scanLoginResponse(buildLoginError(18456, 1, 14, "Login failed for user 'x'."), error);
  ASSERT_TRUE(scan) << error;
  EXPECT_EQ(scan->error, 18456u);
  EXPECT_TRUE(scan->fully_scanned) << "the built ERROR and DONE tokens are well formed";
}

TEST(LoginResponse, BuildsLoginError) {
  const std::string e = buildLoginError(18456, 1, 14, "no");
  // ERROR, length, number, state, class, MsgText "no", ServerName, ProcName, line.
  EXPECT_EQ(e.substr(0, 15), std::string("\xaa\x12\x00\x18\x48\x00\x00\x01\x0e\x02\x00n\0o\0", 15));
  EXPECT_EQ(e.size(), 3u + 18 + 13); // ERROR header, its data, DONE.
}

TEST(Utf16, FromUtf8) {
  EXPECT_EQ(utf8ToUtf16le("a\xc3\xa9\xf0\x9f\x98\x80"),
            std::string("a\0\xe9\0\x3d\xd8\x00\xde", 8));
  EXPECT_EQ(utf8ToUtf16le("\xff"), std::string("\xfd\xff", 2));
  EXPECT_EQ(utf16leToUtf8(utf8ToUtf16le("caf\xc3\xa9 \xf0\x9f\x98\x80")),
            "caf\xc3\xa9 \xf0\x9f\x98\x80");
}

// (0 = as recorded). Direction order is kept, as on a real connection.
void replay(ConnectionTracker& t, const std::vector<Event>& events, size_t chunk) {
  for (const Event& e : events) {
    const size_t step = chunk == 0 ? e.bytes.size() : chunk;
    for (size_t pos = 0; pos < e.bytes.size(); pos += step) {
      const std::string_view part = std::string_view(e.bytes).substr(pos, step);
      auto error = e.direction == Direction::ClientToServer ? t.onClientData(part)
                                                             : t.onServerData(part);
      ASSERT_FALSE(error) << *error << " (chunk " << chunk << ")";
    }
  }
}

class FixtureReplay : public ::testing::TestWithParam<size_t> {};

TEST_P(FixtureReplay, Odbc17LoginOnly) {
  const auto events = loadFixture("odbc17_login_only");
  ConnectionTracker t;
  replay(t, events, GetParam());
  EXPECT_TRUE(t.parsing());
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::LoginOnly);
  const auto& c = t.stats(Direction::ClientToServer);
  const auto& s = t.stats(Direction::ServerToClient);
  EXPECT_GE(c.tls_records, 1u) << "LOGIN7 travels as raw TLS";
  EXPECT_EQ(s.tls_records, 0u) << "the server answers in plain TDS";
  EXPECT_GE(c.tds_messages, 4u) << "PRELOGIN, handshake, then plain SQL batches";
  EXPECT_EQ(t.packetSize(), 4096u) << "from the plaintext login response";
}

TEST_P(FixtureReplay, Odbc18Mandatory) {
  const auto events = loadFixture("odbc18_mandatory");
  ConnectionTracker t;
  replay(t, events, GetParam());
  EXPECT_TRUE(t.parsing());
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::Full);
  EXPECT_GE(t.stats(Direction::ClientToServer).tls_records, 1u);
  EXPECT_GE(t.stats(Direction::ServerToClient).tls_records, 1u);
  EXPECT_FALSE(t.packetSize()) << "the login response is encrypted";
}

TEST_P(FixtureReplay, Odbc17Mars) {
  const auto events = loadFixture("odbc17_mars");
  ConnectionTracker t;
  replay(t, events, GetParam());
  EXPECT_TRUE(t.parsing());
  EXPECT_EQ(t.encryptionMode(), EncryptionMode::LoginOnly);
  EXPECT_TRUE(t.marsEnabled());
  // SYN, DATA..., FIN from the client; DATA back from the server.
  EXPECT_GE(t.stats(Direction::ClientToServer).smp_packets, 3u);
  EXPECT_GE(t.stats(Direction::ServerToClient).smp_packets, 1u);
}

INSTANTIATE_TEST_SUITE_P(Chunks, FixtureReplay, ::testing::Values(0, 1, 3, 7, 64, 1000));

} // namespace
} // namespace MssqlProxy
