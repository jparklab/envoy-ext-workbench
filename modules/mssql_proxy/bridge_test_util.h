#pragma once

// Test-only: a simulated TDS 7.x client and SQL Server around a TlsBridge.
// Both peers run real TLS (BoringSSL) inside PRELOGIN packets, as the drivers
// do. Throwaway certificates only.

#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <functional>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tds.h"
#include "test_util.h"
#include "tls_bridge.h"

namespace MssqlProxy {
namespace test {

inline constexpr uint8_t kEncOff = 0x00;
inline constexpr uint8_t kEncOn = 0x01;
inline constexpr uint8_t kEncNotSup = 0x02;
inline constexpr uint8_t kEncReq = 0x03;
inline constexpr uint8_t kEncClientCert = 0x80;

// ---------------------------------------------------------------- certificates

struct Cert {
  std::string cert_pem;
  std::string key_pem;
};

// Throwaway self-signed P-256 certificate for "name", also valid for 127.0.0.1.
// key_usage, when set, is added as the keyUsage extension.
inline Cert makeCert(const std::string& name, const char* key_usage = nullptr) {
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

inline const Cert& proxyCert() {
  static const Cert c = makeCert("proxy.test");
  return c;
}
// Like a typical SQL Server certificate: self-signed, but its key usage
// doesn't allow signing certificates, so it can only be trusted as itself.
inline const Cert& serverCert() {
  static const Cert c = makeCert("db.test", "critical,digitalSignature,keyEncipherment");
  return c;
}

inline TlsSettings settings(const std::string& server_name = "db.test") {
  TlsSettings s;
  s.cert_pem = proxyCert().cert_pem;
  s.key_pem = proxyCert().key_pem;
  s.upstream_ca_pem = serverCert().cert_pem;
  s.upstream_server_name = server_name;
  return s;
}

inline std::shared_ptr<const TlsContexts> contexts(const TlsSettings& s = settings()) {
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
          std::shared_ptr<const TlsContexts> ctx = contexts(), BridgeOptions options = {},
          std::optional<bool> server_mars = std::nullopt)
      : client(false, client_enc, mars), server(true, server_enc, server_mars.value_or(mars)),
        bridge(std::move(ctx), options), chunk(chunk) {}

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
      take(out);
      runWork();
    }
  }

  // Runs the bridge's pending Kerberos steps here, as the filter does on its
  // worker pool, and delivers what resuming sends.
  void runWork() {
    while (!error && !hold_work && bridge.waiting()) {
      std::function<void()> work = bridge.takeWork();
      if (!work) {
        ADD_FAILURE() << "the bridge waits without a step to run";
        return;
      }
      work();
      ++steps_run;
      BridgeOutput out;
      error = bridge.resume(out);
      take(out);
    }
  }

  void take(const BridgeOutput& out) {
    if (error) {
      if (error->kind == BridgeError::Kind::Denied) {
        client.receive(out.to_client); // The refusal is meant to be delivered.
      }
      return;
    }
    to_server_wire += out.to_server;
    to_client_wire += out.to_client;
    server.receive(out.to_server);
    client.receive(out.to_client);
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
  std::string to_client_wire; // Everything the bridge sent the client.
  bool hold_work = false;     // Leave the bridge's Kerberos steps pending.
  size_t steps_run = 0;
};

inline std::string loginResponse(std::string_view packet_size) {
  return loginAck() + envChangePacketSize(packet_size, "4096") + done();
}

// A SQL login long enough to span two 512-byte packets, with the password in
// the first one.
inline Login7Fields longLogin() {
  Login7Fields f;
  f.host = std::string(128, 'h');
  f.app = std::string(128, 'a');
  f.library = std::string(128, 'l');
  return f;
}

// Sends LOGIN7 as mssql-jdbc does under login-only encryption: the first
// packet over TLS, the rest in plain TDS.
inline void sendSplitLogin7(Peer& client, std::string_view payload, size_t packet_size) {
  const std::string wire = makeTdsMessage(kTdsLogin7, payload, packet_size);
  const size_t first = (static_cast<uint8_t>(wire[2]) << 8) | static_cast<uint8_t>(wire[3]);
  client.sendRaw(std::string_view(wire).substr(0, first), /*over_tls=*/true);
  client.sendRaw(std::string_view(wire).substr(first), /*over_tls=*/false);
}

// What a captured wire carried after the PRELOGIN exchange, one character per
// unit: 'T' a TLS record, 'L' a plain LOGIN7 packet, 'P' any other plain TDS
// packet. PRELOGIN packets (the TLS handshake) are left out.
inline std::string wireShape(std::string_view wire) {
  struct Shape : UnitSink {
    std::optional<std::string> onUnit(const Unit& unit) override {
      if (unit.kind == UnitKind::TlsRecord) {
        shape += 'T';
      } else if (unit.type != kTdsPrelogin) {
        shape += unit.type == kTdsLogin7 ? 'L' : 'P';
      }
      return std::nullopt;
    }
    std::string shape;
  } sink;
  StreamSplitter splitter;
  if (auto error = splitter.feed(wire, sink)) {
    return "error: " + *error;
  }
  return sink.shape;
}

inline std::string smpPacket(uint8_t flags, std::string_view data) {
  std::string p{static_cast<char>(kSmpId), static_cast<char>(flags), 0, 0};
  const size_t len = kSmpHeaderSize + data.size();
  p.append({static_cast<char>(len), static_cast<char>(len >> 8), static_cast<char>(len >> 16),
            static_cast<char>(len >> 24)});
  p.append(8, '\0');
  return p + std::string(data);
}

} // namespace test
} // namespace MssqlProxy
