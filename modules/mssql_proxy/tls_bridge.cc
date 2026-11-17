#include "tls_bridge.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <climits>
#include <format>
#include <utility>

namespace MssqlProxy {

namespace {

// Packet size for the messages the bridge builds itself (PRELOGIN and the TLS
// handshake), before the login negotiates one: the TDS default.
constexpr size_t kHandshakePacketSize = 4096;
// Client bytes kept until its PRELOGIN completes, to pass a non-TDS 7.x
// connection through untouched.
constexpr size_t kMaxClientRaw = 64 * 1024;
// Plain text held while the server's TLS handshake finishes (normally just
// LOGIN7).
constexpr size_t kMaxPendingToServer = 256 * 1024;
constexpr size_t kMaxPreloginMessage = kTdsMaxPacketSize;
// A login takes a few server messages (SSPI rounds, then LOGINACK).
constexpr size_t kMaxLoginMessages = 8;
constexpr size_t kMaxLoginMessageSize = 64 * 1024;

const char* sideName(Direction from) {
  return from == Direction::ClientToServer ? "client" : "server";
}

// what, followed by BoringSSL's queued errors.
std::string sslError(std::string what) {
  while (const uint32_t e = ERR_get_error()) {
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    what += ": ";
    what += buf;
  }
  return what;
}

BridgeError protocolError(std::string message) {
  return {BridgeError::Kind::Protocol, std::move(message)};
}
BridgeError tlsError(std::string message) { return {BridgeError::Kind::Tls, std::move(message)}; }

bssl::UniquePtr<BIO> memBio(const std::string& pem) {
  return bssl::UniquePtr<BIO>(BIO_new_mem_buf(pem.data(), static_cast<ptrdiff_t>(pem.size())));
}

bssl::UniquePtr<X509> readCert(BIO* bio) {
  return bssl::UniquePtr<X509>(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr));
}

bool isIpAddress(const std::string& s) {
  in_addr a4;
  in6_addr a6;
  return inet_pton(AF_INET, s.c_str(), &a4) == 1 || inet_pton(AF_INET6, s.c_str(), &a6) == 1;
}

void configureCommon(SSL_CTX* ctx) {
  // TDS 7.x carries the handshake in PRELOGIN packets and clients speak TLS
  // 1.2 there; SQL Server offers TLS 1.3 only to TDS 8.0 strict.
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  // Full handshakes only: no session resumption on either leg.
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
}

} // namespace

std::shared_ptr<const TlsContexts> TlsContexts::create(const TlsSettings& settings,
                                                       std::string& error) {
  ERR_clear_error();
  std::shared_ptr<TlsContexts> contexts(new TlsContexts());
  contexts->downstream_.reset(SSL_CTX_new(TLS_server_method()));
  contexts->upstream_.reset(SSL_CTX_new(TLS_client_method()));
  if (!contexts->downstream_ || !contexts->upstream_) {
    error = sslError("cannot create TLS contexts");
    return nullptr;
  }
  SSL_CTX* down = contexts->downstream_.get();
  SSL_CTX* up = contexts->upstream_.get();
  configureCommon(down);
  configureCommon(up);

  // Certificate chain and key presented to clients.
  bssl::UniquePtr<BIO> cert_bio = memBio(settings.cert_pem);
  bssl::UniquePtr<X509> leaf = readCert(cert_bio.get());
  if (!leaf || !SSL_CTX_use_certificate(down, leaf.get())) {
    error = sslError("cannot load the certificate");
    return nullptr;
  }
  while (bssl::UniquePtr<X509> intermediate = readCert(cert_bio.get())) {
    if (!SSL_CTX_add1_chain_cert(down, intermediate.get())) {
      error = sslError("cannot load the certificate chain");
      return nullptr;
    }
  }
  ERR_clear_error(); // The read that ended the loop failed at the end of the PEM data.
  bssl::UniquePtr<BIO> key_bio = memBio(settings.key_pem);
  bssl::UniquePtr<EVP_PKEY> key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  if (!key || !SSL_CTX_use_PrivateKey(down, key.get())) {
    error = sslError("cannot load the private key");
    return nullptr;
  }
  if (!SSL_CTX_check_private_key(down)) {
    error = sslError("the private key does not match the certificate");
    return nullptr;
  }

  // Verification of the SQL Server's certificate.
  if (settings.upstream_verify) {
    X509_STORE* store = SSL_CTX_get_cert_store(up);
    bssl::UniquePtr<BIO> ca_bio = memBio(settings.upstream_ca_pem);
    size_t loaded = 0;
    while (bssl::UniquePtr<X509> ca = readCert(ca_bio.get())) {
      if (!X509_STORE_add_cert(store, ca.get())) {
        error = sslError("cannot load the upstream CA certificates");
        return nullptr;
      }
      loaded++;
    }
    ERR_clear_error();
    if (loaded == 0) {
      error = "no upstream CA certificate to verify the server with";
      return nullptr;
    }
    // Every certificate given is a trust anchor, so a server's own
    // self-signed certificate can be pinned: SQL Server certificates usually
    // can't sign certificates (key usage), so they don't verify as their own
    // issuer.
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    SSL_CTX_set_verify(up, SSL_VERIFY_PEER, nullptr);
  } else {
    SSL_CTX_set_verify(up, SSL_VERIFY_NONE, nullptr);
  }
  contexts->server_name_ = settings.upstream_server_name;
  return contexts;
}

TlsBridge::TlsBridge(std::shared_ptr<const TlsContexts> contexts)
    : contexts_(std::move(contexts)),
      wire_sinks_{Sink(*this, Direction::ClientToServer, false),
                  Sink(*this, Direction::ServerToClient, false)},
      plain_sinks_{Sink(*this, Direction::ClientToServer, true),
                   Sink(*this, Direction::ServerToClient, true)} {}

std::optional<std::string> TlsBridge::Sink::onUnit(const Unit& unit) {
  std::optional<BridgeError> error = decrypted_ ? bridge_.onPlainUnit(direction_, unit, true)
                                                : bridge_.onWireUnit(direction_, unit);
  if (!error) {
    return std::nullopt;
  }
  bridge_.error_ = std::move(error);
  return bridge_.error_->message;
}

std::optional<BridgeError> TlsBridge::feed(Direction d, std::string_view data,
                                           BridgeOutput& out) {
  if (data.empty()) {
    return std::nullopt;
  }
  if (passive_) {
    (d == Direction::ClientToServer ? out.to_server : out.to_client).append(data);
    return std::nullopt;
  }
  if (d == Direction::ClientToServer && !client_prelogin_) {
    if (client_raw_.size() + data.size() > kMaxClientRaw) {
      return protocolError("client: too much data before its PRELOGIN completed");
    }
    client_raw_.append(data);
  }

  out_ = &out;
  std::optional<std::string> message = wire_[index(d)].feed(data, wire_sinks_[index(d)]);
  out_ = nullptr;
  std::optional<BridgeError> error = std::exchange(error_, std::nullopt);

  if (passive_) {
    // Not TDS 7.x after all: send on everything the client sent, untouched.
    out.to_server.append(client_raw_);
    client_raw_.clear();
    return std::nullopt;
  }
  if (!message) {
    return std::nullopt;
  }
  if (!error) {
    error = protocolError(*message); // Framing error from the splitter itself.
  }
  error->message = std::format("{}: {}", sideName(d), error->message);
  return error;
}

std::optional<BridgeError> TlsBridge::onWireUnit(Direction d, const Unit& unit) {
  Stage& stage = stage_[index(d)];
  const bool client = d == Direction::ClientToServer;
  const bool tls = unit.kind == UnitKind::TlsRecord;

  switch (stage) {
  case Stage::Prelogin:
    return onPreloginUnit(d, unit);

  case Stage::Handshake: {
    if (unit.kind != UnitKind::TdsPacket || unit.type != kTdsPrelogin) {
      return protocolError(std::format("{} type 0x{:02x} during the TLS handshake",
                                       unitKindName(unit.kind), unit.type));
    }
    const std::string_view payload = unit.payload();
    if (BIO_write(legOf(d).rbio, payload.data(), static_cast<int>(payload.size())) !=
        static_cast<int>(payload.size())) {
      return tlsError("cannot buffer TLS handshake data");
    }
    return driveHandshake(d);
  }

  case Stage::Tls:
    if (tls) {
      // Under login-only the server never sends raw TLS: it answers the
      // client's encrypted LOGIN7 in plain TDS.
      if (!client && mode_ == EncryptionMode::LoginOnly) {
        return protocolError("raw TLS from the server under login-only encryption");
      }
      return decrypt(d, unit.bytes);
    }
    if (mode_ == EncryptionMode::LoginOnly) {
      const Stage other_stage = stage_[index(other(d))];
      if (!client && other_stage == Stage::Tls) {
        stage = Stage::Plain; // The login response, after the client's encrypted LOGIN7.
        return onPlainUnit(d, unit, false);
      }
      if (client && other_stage == Stage::Plain) {
        if (plain_[index(d)].bufferedBytes() != 0) {
          return protocolError("plain TDS while a TLS-carried packet is incomplete");
        }
        stage = Stage::Plain; // Back to plain TDS once the login is answered.
        return onPlainUnit(d, unit, false);
      }
    }
    return protocolError(std::format("plain {} type 0x{:02x} after TLS under {} encryption",
                                     unitKindName(unit.kind), unit.type,
                                     encryptionModeName(mode_)));

  case Stage::Plain:
    if (tls) {
      return protocolError(std::format("raw TLS record in plain TDS under {} encryption",
                                       encryptionModeName(mode_)));
    }
    return onPlainUnit(d, unit, false);
  }
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::onPreloginUnit(Direction d, const Unit& unit) {
  const bool client = d == Direction::ClientToServer;
  if (client && client_prelogin_) {
    return protocolError("data before the server's PRELOGIN response");
  }
  if (!client && !client_prelogin_) {
    return protocolError("data before the client's PRELOGIN");
  }
  const uint8_t want = client ? kTdsPrelogin : kTdsTabularResult;
  if (unit.kind != UnitKind::TdsPacket || unit.type != want) {
    if (client && prelogin_payload_.empty()) {
      // Doesn't open with PRELOGIN: not a TDS 7.x conversation we understand.
      passive_ = true;
      return protocolError("passive");
    }
    return protocolError(std::format("expected a PRELOGIN {}, got {} type 0x{:02x}",
                                     client ? "message" : "response", unitKindName(unit.kind),
                                     unit.type));
  }
  if (prelogin_payload_.size() + unit.payload().size() > kMaxPreloginMessage) {
    return protocolError("PRELOGIN message too large");
  }
  prelogin_payload_.append(unit.payload());
  if (!unit.eom) {
    return std::nullopt;
  }
  std::string payload = std::move(prelogin_payload_);
  prelogin_payload_.clear();
  return onPreloginMessage(d, payload);
}

std::optional<BridgeError> TlsBridge::onPreloginMessage(Direction d, std::string& payload) {
  std::string error;
  std::optional<PreloginOptions> options = parsePrelogin(payload, error);
  if (!options) {
    return protocolError(error);
  }

  if (d == Direction::ClientToServer) {
    if (options->client_cert) {
      // A certificate login authenticates the client in the TLS handshake,
      // which ends at this proxy; ask the server for a normal login instead.
      payload[*options->encryption_offset] &= 0x7f;
      client_cert_cleared_ = true;
    }
    client_prelogin_ = *options;
    client_raw_.clear();
    client_raw_.shrink_to_fit();
    out_->to_server += makeTdsMessage(kTdsPrelogin, payload, kHandshakePacketSize);
    return std::nullopt;
  }

  const auto client = client_prelogin_->encryption.value_or(PreloginEncryption::Off);
  const auto server = options->encryption.value_or(PreloginEncryption::Off);
  if (client == PreloginEncryption::NotSupported || server == PreloginEncryption::NotSupported) {
    mode_ = EncryptionMode::None;
  } else if (server == PreloginEncryption::Off) {
    mode_ = EncryptionMode::LoginOnly;
  } else {
    mode_ = EncryptionMode::Full;
  }
  mars_ = client_prelogin_->mars.value_or(false) && options->mars.value_or(false);
  for (auto* splitters : {&wire_, &plain_}) {
    for (StreamSplitter& s : *splitters) {
      s.setMarsEnabled(mars_);
    }
  }
  out_->to_client += makeTdsMessage(kTdsTabularResult, payload, kHandshakePacketSize);

  if (mode_ == EncryptionMode::None) {
    stage_ = {Stage::Plain, Stage::Plain};
    return std::nullopt;
  }

  // Both TLS sessions start now: the client's when its ClientHello arrives,
  // the server's right away with our ClientHello.
  ERR_clear_error();
  for (auto [leg, ctx] : {std::pair{&down_, contexts_->downstream()},
                          std::pair{&up_, contexts_->upstream()}}) {
    leg->ssl.reset(SSL_new(ctx));
    if (!leg->ssl) {
      return tlsError(sslError("cannot create a TLS session"));
    }
    leg->rbio = BIO_new(BIO_s_mem());
    leg->wbio = BIO_new(BIO_s_mem());
    if (leg->rbio == nullptr || leg->wbio == nullptr) {
      BIO_free(leg->rbio);
      BIO_free(leg->wbio);
      leg->rbio = leg->wbio = nullptr;
      return tlsError(sslError("cannot create TLS buffers"));
    }
    SSL_set_bio(leg->ssl.get(), leg->rbio, leg->wbio);
  }
  SSL_set_accept_state(down_.ssl.get());
  SSL_set_connect_state(up_.ssl.get());
  const std::string& name = contexts_->upstreamServerName();
  if (!name.empty()) {
    X509_VERIFY_PARAM* param = SSL_get0_param(up_.ssl.get());
    const bool ok = isIpAddress(name)
                        ? X509_VERIFY_PARAM_set1_ip_asc(param, name.c_str()) == 1
                        : SSL_set_tlsext_host_name(up_.ssl.get(), name.c_str()) == 1 &&
                              X509_VERIFY_PARAM_set1_host(param, name.data(), name.size()) == 1;
    if (!ok) {
      return tlsError(sslError("cannot set the upstream server name"));
    }
  }
  stage_ = {Stage::Handshake, Stage::Handshake};
  return driveHandshake(Direction::ServerToClient);
}

std::optional<BridgeError> TlsBridge::driveHandshake(Direction from) {
  Leg& leg = legOf(from);
  ERR_clear_error();
  const int result = SSL_do_handshake(leg.ssl.get());
  // Each flight goes back as one PRELOGIN message.
  if (std::string flight = drainTls(leg); !flight.empty()) {
    replyOutput(from) += makeTdsMessage(kTdsPrelogin, flight, kHandshakePacketSize);
  }
  if (result == 1) {
    leg.handshake_done = true;
    stage_[index(from)] = Stage::Tls;
    if (BIO_pending(leg.rbio) != 0) {
      return protocolError("data after the TLS handshake in a PRELOGIN packet");
    }
    if (from == Direction::ServerToClient && !pending_to_server_.empty()) {
      std::string pending = std::move(pending_to_server_);
      pending_to_server_.clear();
      return sendEncrypted(Direction::ClientToServer, pending);
    }
    return std::nullopt;
  }
  if (SSL_get_error(leg.ssl.get(), result) == SSL_ERROR_WANT_READ) {
    return std::nullopt;
  }
  std::string what = std::format("TLS handshake with the {} failed", sideName(from));
  if (from == Direction::ServerToClient) {
    const long verify = SSL_get_verify_result(leg.ssl.get());
    if (verify != X509_V_OK) {
      what += std::format(" (certificate: {}", X509_verify_cert_error_string(verify));
      if (bssl::UniquePtr<X509> peer{SSL_get_peer_certificate(leg.ssl.get())}) {
        char subject[256];
        char issuer[256];
        X509_NAME_oneline(X509_get_subject_name(peer.get()), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(peer.get()), issuer, sizeof(issuer));
        what += std::format("; subject {}, issuer {}", subject, issuer);
      }
      what += ")";
    }
  }
  return tlsError(sslError(std::move(what)));
}

std::optional<BridgeError> TlsBridge::decrypt(Direction from, std::string_view record) {
  Leg& leg = legOf(from);
  if (BIO_write(leg.rbio, record.data(), static_cast<int>(record.size())) !=
      static_cast<int>(record.size())) {
    return tlsError("cannot buffer TLS data");
  }
  char buf[16 * 1024];
  while (true) {
    ERR_clear_error();
    const int n = SSL_read(leg.ssl.get(), buf, sizeof(buf));
    if (n > 0) {
      if (auto message = plain_[index(from)].feed(std::string_view(buf, n),
                                                   plain_sinks_[index(from)])) {
        std::optional<BridgeError> error = std::exchange(error_, std::nullopt);
        return error ? std::move(*error) : protocolError("in TLS: " + *message);
      }
      continue;
    }
    const int e = SSL_get_error(leg.ssl.get(), n);
    if (e == SSL_ERROR_WANT_READ) {
      break;
    }
    if (e == SSL_ERROR_ZERO_RETURN) {
      // close_notify: close the other leg's TLS the same way.
      Leg& peer = legOf(other(from));
      if (peer.handshake_done) {
        SSL_shutdown(peer.ssl.get());
        forwardOutput(from) += drainTls(peer);
      }
      break;
    }
    return tlsError(sslError(std::format("TLS read from the {} failed", sideName(from))));
  }
  // Anything the session sends back on its own, e.g. an alert.
  replyOutput(from) += drainTls(leg);
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::onPlainUnit(Direction d, const Unit& unit, bool decrypted) {
  if (d == Direction::ClientToServer) {
    if (unit.kind == UnitKind::TdsPacket && unit.type == kTdsLogin7 && unit.eom) {
      login7_messages_++;
    }
  } else if (auto error = scanLoginMessage(unit)) {
    return error;
  }
  // Both legs are in the same mode: what arrived over TLS leaves over TLS.
  if (decrypted) {
    return sendEncrypted(d, unit.bytes);
  }
  forwardOutput(d) += unit.bytes;
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::scanLoginMessage(const Unit& unit) {
  if (!scanning_login_ || unit.kind != UnitKind::TdsPacket || unit.type != kTdsTabularResult) {
    return std::nullopt;
  }
  if (login_message_.size() + unit.payload().size() > kMaxLoginMessageSize) {
    scanning_login_ = false; // Too big to be a login response; stop looking.
    login_message_.clear();
    return std::nullopt;
  }
  login_message_.append(unit.payload());
  if (!unit.eom) {
    return std::nullopt;
  }
  std::string message = std::move(login_message_);
  login_message_.clear();

  std::string error;
  std::optional<LoginResponseScan> scan = scanLoginResponse(message, error);
  if (!scan) {
    return protocolError("login response: " + error);
  }
  if (scan->packet_size) {
    packet_size_ = scan->packet_size;
    setMaxPacketSize(*packet_size_);
  }
  if (scan->login_ack || !scan->fully_scanned || ++login_messages_scanned_ >= kMaxLoginMessages) {
    scanning_login_ = false;
  }
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::sendEncrypted(Direction d, std::string_view plain) {
  if (d == Direction::ClientToServer && !up_.handshake_done) {
    if (pending_to_server_.size() + plain.size() > kMaxPendingToServer) {
      return protocolError("too much client data before the server's TLS handshake finished");
    }
    pending_to_server_.append(plain);
    return std::nullopt;
  }
  Leg& leg = legOf(other(d));
  if (!leg.handshake_done) {
    return protocolError(std::format("data for the {} before its TLS handshake finished",
                                     sideName(other(d))));
  }
  ERR_clear_error();
  while (!plain.empty()) {
    const int n = SSL_write(leg.ssl.get(), plain.data(),
                            static_cast<int>(std::min<size_t>(plain.size(), INT_MAX)));
    if (n <= 0) {
      return tlsError(sslError(std::format("TLS write to the {} failed", sideName(other(d)))));
    }
    plain.remove_prefix(static_cast<size_t>(n));
  }
  forwardOutput(d) += drainTls(leg);
  return std::nullopt;
}

std::string TlsBridge::drainTls(Leg& leg) {
  std::string bytes(BIO_pending(leg.wbio), '\0');
  if (!bytes.empty()) {
    bytes.resize(static_cast<size_t>(
        std::max(0, BIO_read(leg.wbio, bytes.data(), static_cast<int>(bytes.size())))));
  }
  return bytes;
}

void TlsBridge::setMaxPacketSize(size_t size) {
  for (auto* splitters : {&wire_, &plain_}) {
    for (StreamSplitter& s : *splitters) {
      s.setMaxTdsPacketSize(size);
    }
  }
}

} // namespace MssqlProxy
