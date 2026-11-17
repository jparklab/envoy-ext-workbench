// TlsBridge between a simulated TDS 7.x client and SQL Server. Both peers run
// real TLS (BoringSSL) inside PRELOGIN packets, as the drivers do, so these
// tests check that each leg's handshake completes against the bridge and that
// what one peer sends arrives at the other unchanged in plain text.

#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tds.h"
#include "test_util.h"
#include "tls_bridge.h"

namespace MssqlProxy {
namespace {

using namespace test;

constexpr uint8_t kEncOff = 0x00;
constexpr uint8_t kEncOn = 0x01;
constexpr uint8_t kEncNotSup = 0x02;
constexpr uint8_t kEncReq = 0x03;
constexpr uint8_t kEncClientCert = 0x80;

// ---------------------------------------------------------------- certificates

struct Cert {
  std::string cert_pem;
  std::string key_pem;
};

// Throwaway self-signed P-256 certificate for "name", also valid for 127.0.0.1.
// key_usage, when set, is added as the keyUsage extension.
Cert makeCert(const std::string& name, const char* key_usage = nullptr) {
  bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  EXPECT_TRUE(EC_KEY_generate_key(ec.get()));
  bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
  EXPECT_TRUE(EVP_PKEY_assign_EC_KEY(key.get(), ec.release()));

  bssl::UniquePtr<X509> x(X509_new());
  X509_set_version(x.get(), X509_VERSION_3);
  ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);
  X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x.get()), 86400);
  X509_set_pubkey(x.get(), key.get());
  X509_NAME* subject = X509_get_subject_name(x.get());
  X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                             reinterpret_cast<const uint8_t*>(name.c_str()), -1, -1, 0);
  X509_set_issuer_name(x.get(), subject);
  const std::string san = "DNS:" + name + ",IP:127.0.0.1";
  bssl::UniquePtr<X509_EXTENSION> ext(
      X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str()));
  EXPECT_TRUE(ext && X509_add_ext(x.get(), ext.get(), -1));
  if (key_usage != nullptr) {
    bssl::UniquePtr<X509_EXTENSION> ku(
        X509V3_EXT_nconf_nid(nullptr, nullptr, NID_key_usage, key_usage));
    EXPECT_TRUE(ku && X509_add_ext(x.get(), ku.get(), -1));
  }
  EXPECT_TRUE(X509_sign(x.get(), key.get(), EVP_sha256()));

  auto toPem = [](auto write) {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    write(bio.get());
    const uint8_t* data;
    size_t len;
    BIO_mem_contents(bio.get(), &data, &len);
    return std::string(reinterpret_cast<const char*>(data), len);
  };
  return {toPem([&](BIO* b) { PEM_write_bio_X509(b, x.get()); }),
          toPem([&](BIO* b) {
            PEM_write_bio_PrivateKey(b, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
          })};
}

const Cert& proxyCert() {
  static const Cert c = makeCert("proxy.test");
  return c;
}
// Like a typical SQL Server certificate: self-signed, but its key usage
// doesn't allow signing certificates, so it can only be trusted as itself.
const Cert& serverCert() {
  static const Cert c = makeCert("db.test", "critical,digitalSignature,keyEncipherment");
  return c;
}

TlsSettings settings(const std::string& server_name = "db.test") {
  TlsSettings s;
  s.cert_pem = proxyCert().cert_pem;
  s.key_pem = proxyCert().key_pem;
  s.upstream_ca_pem = serverCert().cert_pem;
  s.upstream_server_name = server_name;
  return s;
}

std::shared_ptr<const TlsContexts> contexts(const TlsSettings& s = settings()) {
  std::string error;
  auto c = TlsContexts::create(s, error);
  EXPECT_TRUE(c) << error;
  return c;
}

// ---------------------------------------------------------------- peers

// A TDS 7.x client or server: PRELOGIN exchange, TLS handshake carried in
// PRELOGIN packets, then TDS messages over TLS or plain.
class Peer : public UnitSink {
public:
  Peer(bool server, uint8_t encryption, bool mars)
      : server_(server), encryption_(encryption), mars_(mars) {
    ctx_.reset(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()));
    if (server) {
      bssl::UniquePtr<BIO> c(BIO_new_mem_buf(serverCert().cert_pem.data(), -1));
      bssl::UniquePtr<BIO> k(BIO_new_mem_buf(serverCert().key_pem.data(), -1));
      bssl::UniquePtr<X509> cert(PEM_read_bio_X509(c.get(), nullptr, nullptr, nullptr));
      bssl::UniquePtr<EVP_PKEY> key(PEM_read_bio_PrivateKey(k.get(), nullptr, nullptr, nullptr));
      SSL_CTX_use_certificate(ctx_.get(), cert.get());
      SSL_CTX_use_PrivateKey(ctx_.get(), key.get());
    }
    ssl_.reset(SSL_new(ctx_.get()));
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl_.get(), rbio_, wbio_);
    if (server) {
      SSL_set_accept_state(ssl_.get());
    } else {
      SSL_set_connect_state(ssl_.get());
    }
  }

  // The client opens the connection with its PRELOGIN.
  void start() {
    out += makeTdsMessage(kTdsPrelogin, preloginPayload(encryption_, mars_), 4096);
  }

  void receive(std::string_view data) {
    if (auto e = splitter_.feed(data, *this)) {
      failure = *e;
    }
  }

  // Sends one TDS message, over TLS when asked.
  void send(uint8_t type, std::string_view payload, bool over_tls, size_t packet_size = 4096) {
    sendRaw(makeTdsMessage(type, payload, packet_size), over_tls);
  }
  void sendRaw(std::string_view bytes, bool over_tls) {
    if (!over_tls) {
      out += bytes;
      return;
    }
    ASSERT_EQ(SSL_write(ssl_.get(), bytes.data(), static_cast<int>(bytes.size())),
              static_cast<int>(bytes.size()));
    out += drain();
  }

  std::optional<std::string> onUnit(const Unit& unit) override {
    if (!peer_prelogin) {
      std::string error;
      peer_prelogin = parsePrelogin(unit.payload(), error);
      if (!peer_prelogin) {
        return error;
      }
      if (server_) {
        out += makeTdsMessage(kTdsTabularResult, preloginPayload(encryption_, mars_), 4096);
      }
      const bool tls = (encryption_ & 0x7f) != kEncNotSup &&
                       peer_prelogin->encryption != PreloginEncryption::NotSupported;
      splitter_.setMarsEnabled(mars_ && peer_prelogin->mars.value_or(false));
      if (tls && !server_) {
        handshake();
      }
      return std::nullopt;
    }
    if (unit.kind == UnitKind::TdsPacket && unit.type == kTdsPrelogin && !handshake_done) {
      BIO_write(rbio_, unit.payload().data(), static_cast<int>(unit.payload().size()));
      handshake();
      return std::nullopt;
    }
    if (unit.kind == UnitKind::TlsRecord) {
      BIO_write(rbio_, unit.bytes.data(), static_cast<int>(unit.bytes.size()));
      char buf[16384];
      int n;
      while ((n = SSL_read(ssl_.get(), buf, sizeof(buf))) > 0) {
        received.append(buf, n);
      }
      return std::nullopt;
    }
    received += unit.bytes;
    return std::nullopt;
  }

  std::string out;      // Bytes for the bridge.
  std::string received; // TDS bytes after the PRELOGIN exchange, decrypted if over TLS.
  std::optional<PreloginOptions> peer_prelogin;
  bool handshake_done = false;
  std::optional<std::string> failure;

private:
  void handshake() {
    const int r = SSL_do_handshake(ssl_.get());
    if (std::string flight = drain(); !flight.empty()) {
      out += makeTdsMessage(kTdsPrelogin, flight, 4096);
    }
    if (r == 1) {
      handshake_done = true;
    } else if (SSL_get_error(ssl_.get(), r) != SSL_ERROR_WANT_READ) {
      failure = "peer TLS handshake failed";
    }
  }
  std::string drain() {
    std::string s(BIO_pending(wbio_), '\0');
    BIO_read(wbio_, s.data(), static_cast<int>(s.size()));
    return s;
  }

  bool server_;
  uint8_t encryption_;
  bool mars_;
  bssl::UniquePtr<SSL_CTX> ctx_;
  bssl::UniquePtr<SSL> ssl_;
  BIO* rbio_;
  BIO* wbio_;
  StreamSplitter splitter_;
};

// Client <-> bridge <-> server, moving bytes until nothing is left to move.
// Each delivery to the bridge is cut into pieces of `chunk` bytes (0: whole).
struct Harness {
  Harness(uint8_t client_enc, uint8_t server_enc, size_t chunk, bool mars = false,
          std::shared_ptr<const TlsContexts> ctx = contexts())
      : client(false, client_enc, mars), server(true, server_enc, mars), bridge(std::move(ctx)),
        chunk(chunk) {}

  // Delivers pending bytes until quiet (the server's only unless held back).
  // Returns false on a bridge error.
  bool pump(bool hold_server = false) {
    for (int round = 0; round < 50 && !error; ++round) {
      const bool from_client = !client.out.empty();
      if (from_client) {
        deliver(true);
      }
      const bool from_server = !hold_server && !server.out.empty() && !error;
      if (from_server) {
        deliver(false);
      }
      if (!from_client && !from_server) {
        break;
      }
    }
    EXPECT_FALSE(client.failure) << *client.failure;
    EXPECT_FALSE(server.failure) << *server.failure;
    return !error;
  }

  // Delivers everything one peer has sent so far.
  void deliver(bool from_client) {
    const std::string data = std::exchange(from_client ? client.out : server.out, "");
    const size_t step = chunk == 0 ? data.size() : chunk;
    for (size_t pos = 0; pos < data.size() && !error; pos += step) {
      BridgeOutput out;
      const std::string_view piece = std::string_view(data).substr(pos, step);
      error = from_client ? bridge.onClientData(piece, out) : bridge.onServerData(piece, out);
      if (error) {
        return;
      }
      to_server_wire += out.to_server;
      server.receive(out.to_server);
      client.receive(out.to_client);
    }
  }

  // The PRELOGIN exchange and both TLS handshakes.
  bool connect() {
    client.start();
    return pump();
  }

  std::string message() const { return error ? error->message : ""; }

  Peer client;
  Peer server;
  TlsBridge bridge;
  size_t chunk;
  std::optional<BridgeError> error;
  std::string to_server_wire; // Everything the bridge sent the server.
};

std::string loginResponse(std::string_view packet_size) {
  return loginAck() + envChangePacketSize(packet_size, "4096") + done();
}

std::string smpPacket(uint8_t flags, std::string_view data) {
  std::string p{static_cast<char>(kSmpId), static_cast<char>(flags), 0, 0};
  const size_t len = kSmpHeaderSize + data.size();
  p.append({static_cast<char>(len), static_cast<char>(len >> 8), static_cast<char>(len >> 16),
            static_cast<char>(len >> 24)});
  p.append(8, '\0');
  return p + std::string(data);
}

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

  const std::string login7(300, 'L');
  h.client.send(kTdsLogin7, login7, /*over_tls=*/true);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, login7, 4096));
  EXPECT_EQ(h.bridge.login7Messages(), 1u);
  EXPECT_EQ(h.to_server_wire.find(login7), std::string::npos) << "LOGIN7 sent in clear";

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

  h.client.send(kTdsLogin7, std::string(200, 'L'), true);
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
  h.client.send(kTdsLogin7, "login", false);
  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, "login", 4096));
  EXPECT_EQ(h.bridge.login7Messages(), 1u);
}

TEST_P(BridgeModes, Mars) {
  Harness h(kEncOff, kEncOn, GetParam(), /*mars=*/true);
  ASSERT_TRUE(h.connect()) << h.message();
  EXPECT_TRUE(h.bridge.marsEnabled());
  h.client.send(kTdsLogin7, "login", true);
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
  h.client.send(kTdsLogin7, "login", true);
  ASSERT_TRUE(h.pump(/*hold_server=*/true)) << h.message();
  EXPECT_TRUE(h.server.received.empty());

  ASSERT_TRUE(h.pump()) << h.message();
  EXPECT_TRUE(h.bridge.tlsEstablished());
  EXPECT_EQ(h.server.received, makeTdsMessage(kTdsLogin7, "login", 4096));
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

} // namespace
} // namespace MssqlProxy
