#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tds.h"
#include "tds_connection.h"

namespace MssqlProxy {
namespace {

// ---------------------------------------------------------------- helpers

std::string tdsPacket(uint8_t type, bool eom, std::string_view payload) {
  const size_t len = kTdsHeaderSize + payload.size();
  std::string p;
  p.push_back(static_cast<char>(type));
  p.push_back(static_cast<char>(eom ? kTdsStatusEom : 0));
  p.push_back(static_cast<char>(len >> 8));
  p.push_back(static_cast<char>(len & 0xff));
  p.append({0, 0, 1, 0}); // SPID, packet id, window.
  p.append(payload);
  return p;
}

std::string tlsRecord(uint8_t content_type, std::string_view payload) {
  std::string r;
  r.push_back(static_cast<char>(content_type));
  r.append({0x03, 0x03});
  r.push_back(static_cast<char>(payload.size() >> 8));
  r.push_back(static_cast<char>(payload.size() & 0xff));
  r.append(payload);
  return r;
}

// PRELOGIN payload with VERSION, ENCRYPTION and (optionally) MARS options.
std::string preloginPayload(uint8_t encryption, std::optional<uint8_t> mars = std::nullopt) {
  const size_t options = mars ? 3 : 2;
  const size_t table = options * 5 + 1;
  std::string t, data;
  auto add = [&](uint8_t token, std::string_view value) {
    const size_t offset = table + data.size();
    t.push_back(static_cast<char>(token));
    t.push_back(static_cast<char>(offset >> 8));
    t.push_back(static_cast<char>(offset & 0xff));
    t.push_back(0);
    t.push_back(static_cast<char>(value.size()));
    data.append(value);
  };
  add(0x00, std::string("\x10\x00\x00\x00\x00\x00", 6)); // VERSION
  add(0x01, std::string(1, static_cast<char>(encryption)));
  if (mars) {
    add(0x04, std::string(1, static_cast<char>(*mars)));
  }
  t.push_back(static_cast<char>(0xff));
  return t + data;
}

struct Collect : UnitSink {
  std::vector<Unit> units;
  std::vector<std::string> bytes; // Copies: Unit views die after the callback.
  std::optional<std::string> onUnit(const Unit& u) override {
    units.push_back(u);
    bytes.emplace_back(u.bytes);
    return std::nullopt;
  }
};

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

// ---------------------------------------------------------------- login response

std::string le16(size_t v) {
  return std::string{static_cast<char>(v & 0xff), static_cast<char>((v >> 8) & 0xff)};
}

std::string bVarchar(std::string_view ascii) {
  std::string s(1, static_cast<char>(ascii.size()));
  for (char c : ascii) {
    s.push_back(c);
    s.push_back(0);
  }
  return s;
}

std::string envChangePacketSize(std::string_view new_value, std::string_view old_value) {
  const std::string data = std::string(1, 4) + bVarchar(new_value) + bVarchar(old_value);
  return std::string(1, static_cast<char>(0xe3)) + le16(data.size()) + data;
}

std::string loginAck() {
  const std::string data(10, 'x');
  return std::string(1, static_cast<char>(0xad)) + le16(data.size()) + data;
}

std::string done() { return std::string(1, static_cast<char>(0xfd)) + std::string(12, '\0'); }

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
