#include "tls_bridge.h"

#include <arpa/inet.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/obj.h>
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
// A client SSPI message (MS-TDS caps the SSPI data of LOGIN7 alike).
constexpr size_t kMaxSspiMessageSize = kMaxLogin7Size;
// Data held while a Kerberos step runs (normally none: both peers wait).
constexpr size_t kMaxHeldInput = 64 * 1024;
// What SQL Server sends for a failed login: error 18456, state 1 (the state
// clients see), severity 14.
constexpr uint32_t kLoginFailedError = 18456;

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

// tls-server-end-point (RFC 5929): a hash of the certificate with its
// signature's hash function, SHA-256 in place of MD5 and SHA-1.
std::string tlsServerEndPoint(X509* cert) {
  int digest_nid = NID_undef;
  int pkey_nid = NID_undef;
  const EVP_MD* md = nullptr;
  if (OBJ_find_sigid_algs(X509_get_signature_nid(cert), &digest_nid, &pkey_nid)) {
    md = EVP_get_digestbynid(digest_nid);
  }
  if (md == nullptr || digest_nid == NID_md5 || digest_nid == NID_sha1) {
    md = EVP_sha256();
  }
  uint8_t hash[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (!X509_digest(cert, md, hash, &len)) {
    return {};
  }
  return std::string(reinterpret_cast<const char*>(hash), len);
}

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

namespace {

// VERSION in the local PRELOGIN answer: SQL Server 16.0.2000 (2022). Clients
// learn the real server version from LOGINACK.
constexpr std::string_view kLocalVersion{"\x10\x00\x07\xd0\x00\x00", 6};

// The mode a client's and a server's ENCRYPTION options lead to.
EncryptionMode negotiatedMode(PreloginEncryption client, PreloginEncryption server) {
  if (client == PreloginEncryption::NotSupported || server == PreloginEncryption::NotSupported) {
    return EncryptionMode::None; // (If the server requires encryption it closes.)
  }
  return server == PreloginEncryption::Off ? EncryptionMode::LoginOnly : EncryptionMode::Full;
}

// The local answer to a client's ENCRYPTION option: what SQL Server answers
// when it doesn't force encryption.
PreloginEncryption localEncryption(PreloginEncryption client) {
  switch (client) {
  case PreloginEncryption::NotSupported:
    return PreloginEncryption::NotSupported;
  case PreloginEncryption::Off:
    return PreloginEncryption::Off;
  case PreloginEncryption::On:
  case PreloginEncryption::Required:
    break;
  }
  return PreloginEncryption::On;
}

BridgeError incompatible(std::string message) {
  return {BridgeError::Kind::Incompatible, std::move(message)};
}

} // namespace

TlsBridge::TlsBridge(std::shared_ptr<const TlsContexts> contexts, BridgeOptions options)
    : contexts_(std::move(contexts)), options_(options),
      wire_sinks_{Sink(*this, Direction::ClientToServer, false),
                  Sink(*this, Direction::ServerToClient, false)},
      plain_sinks_{Sink(*this, Direction::ClientToServer, true),
                   Sink(*this, Direction::ServerToClient, true)},
      auth_(options_.auth) {
  if (options_.auth && options_.auth->terminate) {
    terminate_ = &*options_.auth->terminate;
    upstream_spn_ = terminate_->spn;
  }
}

std::optional<std::string> TlsBridge::Sink::onUnit(const Unit& unit) {
  std::optional<BridgeError> error = decrypted_ ? bridge_.onPlainUnit(direction_, unit)
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
  if (waiting_) {
    std::string& held = held_input_[index(d)];
    if (held.size() + data.size() > kMaxHeldInput) {
      return protocolError(
          std::format("{}: too much data while the proxy's Kerberos step runs", sideName(d)));
    }
    held.append(data);
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
    upstream_started_ = true;
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
  const size_t i = index(d);
  Stage& stage = stage_[i];
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
      // encrypted LOGIN7 in plain TDS.
      if (i == kServer && leg_mode_[i] == EncryptionMode::LoginOnly) {
        return protocolError("raw TLS from the server under login-only encryption");
      }
      return decrypt(d, unit.bytes);
    }
    // MS-TDS: under login-only only the first LOGIN7 packet is encrypted; a
    // longer login (e.g. Kerberos from mssql-jdbc) continues in plain packets.
    // Accepted only after that first packet came whole over TLS.
    if (i == kClient && leg_mode_[i] == EncryptionMode::LoginOnly &&
        unit.kind == UnitKind::TdsPacket && unit.type == kTdsLogin7 && !login_ &&
        !login7_message_.empty() && plain_[i].bufferedBytes() == 0) {
      return onPlainUnit(d, unit);
    }
    // Under login-only a leg turns plain once the login is under way: the
    // server answers LOGIN7 in plain TDS, and the client follows once answered.
    if (leg_mode_[i] == EncryptionMode::LoginOnly && app_sent_[i]) {
      if (plain_[i].bufferedBytes() != 0) {
        return protocolError("plain TDS while a TLS-carried packet is incomplete");
      }
      stage = Stage::Plain;
      return onPlainUnit(d, unit);
    }
    return protocolError(std::format("plain {} type 0x{:02x} after TLS under {} encryption",
                                     unitKindName(unit.kind), unit.type,
                                     encryptionModeName(leg_mode_[i])));

  case Stage::Plain:
    if (tls) {
      return protocolError(std::format("raw TLS record in plain TDS under {} encryption",
                                       encryptionModeName(leg_mode_[i])));
    }
    return onPlainUnit(d, unit);
  }
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::onPreloginUnit(Direction d, const Unit& unit) {
  const bool client = d == Direction::ClientToServer;
  if (client && client_prelogin_) {
    return protocolError("data before the server's PRELOGIN response");
  }
  if (!client && !upstream_started_) {
    return protocolError("data before the PRELOGIN was sent");
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
  return client ? onClientPrelogin(payload) : onServerPrelogin(payload);
}

std::optional<BridgeError> TlsBridge::onClientPrelogin(std::string& payload) {
  std::string error;
  std::optional<PreloginOptions> options = parsePrelogin(payload, error);
  if (!options) {
    return protocolError(error);
  }
  if (options->client_cert) {
    // A certificate login authenticates the client in the TLS handshake,
    // which ends at this proxy; ask the server for a normal login instead.
    payload[*options->encryption_offset] &= 0x7f;
    client_cert_cleared_ = true;
  }
  client_prelogin_ = *options;
  client_raw_.clear();
  client_raw_.shrink_to_fit();
  const PreloginEncryption requested = options->encryption.value_or(PreloginEncryption::Off);
  upstream_encryption_ = requested;

  if (!options_.answer_prelogin) {
    upstream_prelogin_ = makeTdsMessage(kTdsPrelogin, payload, kHandshakePacketSize);
    out_->to_server += upstream_prelogin_;
    upstream_started_ = true;
    return std::nullopt;
  }
  // The proxy can always encrypt toward the server, so it asks for at least
  // login encryption there, even for a client that can't encrypt.
  if (requested == PreloginEncryption::NotSupported && options->encryption_offset) {
    payload[*options->encryption_offset] = static_cast<char>(PreloginEncryption::Off);
    upstream_encryption_ = PreloginEncryption::Off;
  }
  upstream_prelogin_ = makeTdsMessage(kTdsPrelogin, payload, kHandshakePacketSize);

  // Answer locally; the server hears from us once LOGIN7 has been read.
  const PreloginEncryption answer = localEncryption(requested);
  leg_mode_[kClient] = negotiatedMode(requested, answer);
  mars_ = options->mars.value_or(false);
  setMars(kClient, mars_);
  out_->to_client += makeTdsMessage(
      kTdsTabularResult, buildPreloginResponse(*options, answer, kLocalVersion),
      kHandshakePacketSize);
  return startLeg(Direction::ClientToServer);
}

std::optional<BridgeError> TlsBridge::onServerPrelogin(const std::string& payload) {
  std::string error;
  std::optional<PreloginOptions> options = parsePrelogin(payload, error);
  if (!options) {
    return protocolError(error);
  }
  const EncryptionMode mode =
      negotiatedMode(upstream_encryption_, options->encryption.value_or(PreloginEncryption::Off));
  const bool mars = client_prelogin_->mars.value_or(false) && options->mars.value_or(false);

  if (!options_.answer_prelogin) {
    leg_mode_ = {mode, mode};
    mars_ = mars;
    setMars(kClient, mars);
    setMars(kServer, mars);
    out_->to_client += makeTdsMessage(kTdsTabularResult, payload, kHandshakePacketSize);
    if (auto e = startLeg(Direction::ClientToServer)) {
      return e;
    }
    return startLeg(Direction::ServerToClient);
  }

  // The client already has the local answer; the server's must fit it.
  if (options->instance && !options->instance->empty() && (*options->instance)[0] != 0) {
    return incompatible("the server rejected the instance name");
  }
  if (mars != mars_) {
    return incompatible("the server refused MARS, which the client was told it has");
  }
  if (options->nonce || options->fedauth_required.value_or(0) != 0) {
    return incompatible("the server asked for federated authentication, which isn't "
                        "supported when routing on LOGIN7");
  }
  if (leg_mode_[kClient] != EncryptionMode::None && mode == EncryptionMode::None) {
    return incompatible("the server would take the login unencrypted while the client "
                        "encrypts it");
  }
  leg_mode_[kServer] = mode;
  setMars(kServer, mars);
  return startLeg(Direction::ServerToClient);
}

std::optional<BridgeError> TlsBridge::startLeg(Direction from) {
  const size_t i = index(from);
  if (leg_mode_[i] == EncryptionMode::None) {
    stage_[i] = Stage::Plain;
    return i == kServer ? serverReady() : std::nullopt;
  }
  Leg& leg = legOf(from);
  ERR_clear_error();
  leg.ssl.reset(SSL_new(i == kClient ? contexts_->downstream() : contexts_->upstream()));
  if (!leg.ssl) {
    return tlsError(sslError("cannot create a TLS session"));
  }
  leg.rbio = BIO_new(BIO_s_mem());
  leg.wbio = BIO_new(BIO_s_mem());
  if (leg.rbio == nullptr || leg.wbio == nullptr) {
    BIO_free(leg.rbio);
    BIO_free(leg.wbio);
    leg.rbio = leg.wbio = nullptr;
    return tlsError(sslError("cannot create TLS buffers"));
  }
  SSL_set_bio(leg.ssl.get(), leg.rbio, leg.wbio);
  stage_[i] = Stage::Handshake;
  if (i == kClient) {
    SSL_set_accept_state(leg.ssl.get()); // Waits for the client's ClientHello.
    return std::nullopt;
  }

  SSL_set_connect_state(leg.ssl.get());
  const std::string& name = contexts_->upstreamServerName();
  if (!name.empty()) {
    X509_VERIFY_PARAM* param = SSL_get0_param(leg.ssl.get());
    const bool ok = isIpAddress(name)
                        ? X509_VERIFY_PARAM_set1_ip_asc(param, name.c_str()) == 1
                        : SSL_set_tlsext_host_name(leg.ssl.get(), name.c_str()) == 1 &&
                              X509_VERIFY_PARAM_set1_host(param, name.data(), name.size()) == 1;
    if (!ok) {
      return tlsError(sslError("cannot set the upstream server name"));
    }
  }
  return driveHandshake(from); // Our ClientHello.
}

std::optional<BridgeError> TlsBridge::serverReady() {
  server_ready_ = true;
  if (!pending_to_server_.empty()) {
    std::string pending = std::move(pending_to_server_);
    pending_to_server_.clear();
    if (auto error = forward(Direction::ClientToServer, pending)) {
      return error;
    }
  }
  maybeStartInitiate();
  return std::nullopt;
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
    return index(from) == kServer ? serverReady() : std::nullopt;
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

std::optional<BridgeError> TlsBridge::onPlainUnit(Direction d, const Unit& unit) {
  const bool sspi = unit.kind == UnitKind::TdsPacket && unit.type == kTdsSspi;
  const bool terminating = kerberos_ != Kerberos::Off && kerberos_ != Kerberos::Done;
  if (d == Direction::ClientToServer) {
    if (!login_) {
      return readLogin7(unit); // Forwards the message once complete and allowed.
    }
    if (terminating) {
      if (kerberos_ == Kerberos::AwaitClient && sspi) {
        return readClientSspi(unit);
      }
      return protocolError("client data during the proxy's Kerberos login");
    }
    if (auth_.result() == LoginResult::Pending && sspi) {
      return readClientSspi(unit);
    }
  } else if (terminating) {
    return onServerLoginUnit(unit);
  } else if (auto error = scanLoginMessage(unit)) {
    return error;
  }
  return forward(d, unit.bytes);
}

std::optional<BridgeError> TlsBridge::readLogin7(const Unit& unit) {
  if (unit.kind != UnitKind::TdsPacket || unit.type != kTdsLogin7) {
    return protocolError(std::format("expected LOGIN7 from the client, got {} type 0x{:02x}",
                                     unitKindName(unit.kind), unit.type));
  }
  if (login7_message_.size() + unit.payload().size() > kMaxLogin7Size) {
    return protocolError("LOGIN7 too large");
  }
  login7_message_.append(unit.payload());
  login7_wire_.append(unit.bytes);
  if (!unit.eom) {
    return std::nullopt;
  }
  std::string error;
  std::string message = std::move(login7_message_);
  login7_message_.clear();
  login_ = parseLogin7(message, error);
  if (!login_) {
    return protocolError(error);
  }
  if (std::optional<Denial> denial = auth_.onLogin7(*login_)) {
    return deny(*denial);
  }
  if (auth_.terminating()) {
    // The proxy authenticates the client; the server gets this LOGIN7 later,
    // with the proxy's own token.
    login7_wire_.clear();
    login7_payload_ = std::move(message);
    exchange_ = terminate_->terminator->start();
    startAccept(login_->sspi);
    return std::nullopt;
  }
  if (!upstream_started_) {
    // Local PRELOGIN: the server hears from us now, before the held LOGIN7.
    out_->to_server += upstream_prelogin_;
    upstream_started_ = true;
  }
  std::string wire = std::move(login7_wire_);
  login7_wire_.clear();
  return forward(Direction::ClientToServer, wire);
}

std::optional<BridgeError> TlsBridge::readClientSspi(const Unit& unit) {
  if (sspi_message_.size() + unit.payload().size() > kMaxSspiMessageSize) {
    return protocolError("SSPI message too large");
  }
  sspi_message_.append(unit.payload());
  sspi_wire_.append(unit.bytes);
  if (!unit.eom) {
    return std::nullopt;
  }
  if (kerberos_ == Kerberos::AwaitClient) {
    std::string token = std::move(sspi_message_);
    sspi_message_.clear();
    sspi_wire_.clear();
    startAccept(token);
    return std::nullopt;
  }
  std::optional<Denial> denial = auth_.onClientSspi(sspi_message_);
  sspi_message_.clear();
  if (denial) {
    return deny(*denial);
  }
  std::string wire = std::move(sspi_wire_);
  sspi_wire_.clear();
  return forward(Direction::ClientToServer, wire);
}

BridgeError TlsBridge::deny(const Denial& denial) {
  auth_.setDenied();
  const std::string message = makeTdsMessage(
      kTdsTabularResult, buildLoginError(kLoginFailedError, 1, 14, denial.client_text),
      kHandshakePacketSize);
  if (auto error = forward(Direction::ServerToClient, message)) {
    return std::move(*error);
  }
  return {BridgeError::Kind::Denied, denial.reason};
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
  auth_.onServerLoginMessage(*scan);
  if (scan->login_ack || !scan->fully_scanned || ++login_messages_scanned_ >= kMaxLoginMessages) {
    scanning_login_ = false;
  }
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::resume(BridgeOutput& out) {
  if (!waiting_ || work_ || !step_) {
    return protocolError("resumed without a finished Kerberos step");
  }
  waiting_ = false;
  KerberosExchange::Step step = std::move(*step_);
  step_.reset();
  out_ = &out;
  std::optional<BridgeError> error = kerberos_ == Kerberos::Accepting
                                         ? afterAccept(std::move(step))
                                         : afterInitiate(std::move(step));
  out_ = nullptr;
  if (error) {
    return error;
  }
  // What arrived meanwhile, unless another step is pending already.
  for (Direction d : {Direction::ClientToServer, Direction::ServerToClient}) {
    std::string held = std::exchange(held_input_[index(d)], std::string());
    if (!held.empty()) {
      if (waiting_) {
        held_input_[index(d)] = std::move(held);
        continue;
      }
      if (auto e = feed(d, held, out)) {
        return e;
      }
    }
  }
  return std::nullopt;
}

void TlsBridge::startAccept(std::string_view token) {
  auto step = std::make_shared<KerberosExchange::Step>();
  step_ = step;
  work_ = [exchange = exchange_, step, token = std::string(token),
           binding = channelBinding(kClient)] { *step = exchange->accept(token, binding); };
  waiting_ = true;
  kerberos_ = Kerberos::Accepting;
}

std::optional<BridgeError> TlsBridge::afterAccept(KerberosExchange::Step step) {
  if (!step.error.empty()) {
    return deny({"Kerberos login to the proxy failed: " + step.error, loginFailedMessage("")});
  }
  if (!step.complete) {
    if (step.token.empty()) {
      return deny({"Kerberos login to the proxy stalled", loginFailedMessage("")});
    }
    // Another round with the client, answered as the server would.
    kerberos_ = Kerberos::AwaitClient;
    return forward(Direction::ServerToClient,
                   makeTdsMessage(kTdsTabularResult, sspiToken(step.token), kHandshakePacketSize));
  }
  client_final_token_ = std::move(step.token);
  if (std::optional<Denial> denial = auth_.onKerberosAccepted(exchange_->clientPrincipal())) {
    return deny(*denial);
  }
  kerberos_ = Kerberos::Accepted;
  if (!upstream_started_) {
    // Local PRELOGIN: the server hears from us now.
    out_->to_server += upstream_prelogin_;
    upstream_started_ = true;
  }
  maybeStartInitiate();
  return std::nullopt;
}

void TlsBridge::maybeStartInitiate() {
  if (kerberos_ == Kerberos::Accepted && server_ready_) {
    startInitiate({});
  }
}

void TlsBridge::startInitiate(std::string_view token) {
  auto step = std::make_shared<KerberosExchange::Step>();
  step_ = step;
  work_ = [exchange = exchange_, step, token = std::string(token), spn = upstream_spn_,
           binding = channelBinding(kServer)] {
    *step = exchange->initiate(token, spn, binding);
  };
  waiting_ = true;
  kerberos_ = kerberos_ == Kerberos::Accepted ? Kerberos::Initiating : Kerberos::Verifying;
}

std::optional<BridgeError> TlsBridge::afterInitiate(KerberosExchange::Step step) {
  if (!step.error.empty()) {
    return deny({"Kerberos login to the server failed: " + step.error,
                 loginFailedMessage(auth_.identity())});
  }
  upstream_complete_ = step.complete;
  if (kerberos_ == Kerberos::Initiating) {
    if (step.token.empty()) {
      return deny({"Kerberos login to the server failed: no token for the server",
                   loginFailedMessage(auth_.identity())});
    }
    std::string error;
    std::optional<std::string> login = replaceLogin7Sspi(login7_payload_, step.token, error);
    if (!login) {
      return protocolError(error);
    }
    login7_payload_.clear();
    kerberos_ = Kerberos::AwaitServer;
    return forward(Direction::ClientToServer,
                   makeTdsMessage(kTdsLogin7, *login, kHandshakePacketSize));
  }

  // The server's SSPI token has been checked.
  kerberos_ = Kerberos::AwaitServer;
  std::string message = std::exchange(held_message_, std::string());
  if (!held_scan_.login_ack && !held_scan_.error) {
    // A round with the server: it waits for the proxy's next token.
    if (!step.token.empty()) {
      return forward(Direction::ClientToServer,
                     makeTdsMessage(kTdsSspi, step.token, kHandshakePacketSize));
    }
    if (!step.complete) {
      return deny({"Kerberos login to the server stalled", loginFailedMessage(auth_.identity())});
    }
  }
  return finishServerMessage(message, held_scan_);
}

std::optional<BridgeError> TlsBridge::onServerLoginUnit(const Unit& unit) {
  if (unit.kind != UnitKind::TdsPacket || unit.type != kTdsTabularResult) {
    return protocolError(std::format("{} type 0x{:02x} during the proxy's Kerberos login",
                                     unitKindName(unit.kind), unit.type));
  }
  if (kerberos_ != Kerberos::AwaitServer) {
    return protocolError("server message before the proxy's Kerberos login reached it");
  }
  if (server_message_.empty() && unit.bytes.size() >= kTdsHeaderSize) {
    server_spid_ = static_cast<uint16_t>((static_cast<uint8_t>(unit.bytes[4]) << 8) |
                                         static_cast<uint8_t>(unit.bytes[5]));
  }
  if (server_message_.size() + unit.payload().size() > kMaxLoginMessageSize) {
    return protocolError("server login message too large");
  }
  server_message_.append(unit.payload());
  if (!unit.eom) {
    return std::nullopt;
  }
  std::string message = std::exchange(server_message_, std::string());
  if (++login_messages_scanned_ > kMaxLoginMessages) {
    return protocolError("too many server messages during the Kerberos login");
  }
  std::string error;
  std::optional<LoginResponseScan> scan = scanLoginResponse(message, error);
  if (!scan) {
    return protocolError("login response: " + error);
  }
  if (scan->packet_size) {
    packet_size_ = scan->packet_size;
    setMaxPacketSize(*packet_size_);
  }
  if (scan->sspi && !upstream_complete_) {
    held_message_ = std::move(message);
    held_scan_ = std::move(*scan);
    startInitiate(*held_scan_.sspi);
    return std::nullopt;
  }
  return finishServerMessage(message, *scan);
}

std::optional<BridgeError> TlsBridge::finishServerMessage(const std::string& message,
                                                          const LoginResponseScan& scan) {
  if (scan.login_ack && !upstream_complete_) {
    return deny({"SQL Server accepted the login without authenticating itself (mutual "
                 "authentication)",
                 loginFailedMessage(auth_.identity())});
  }
  auth_.onServerLoginMessage(scan);
  // The client gets the proxy's last token in place of the server's, which
  // was meant for the proxy, and in the message the server's came in: SQL
  // Server sends its AP-REP alone, ahead of the login response, and clients
  // wait for the second message (ODBC 17 times out on a merged one). A token
  // is sent once: with the server's final SSPI token, or else with LOGINACK.
  const bool server_token_final = scan.sspi && upstream_complete_ && !scan.error;
  std::string payload = replaceSspiTokens(
      message, scan, scan.login_ack || server_token_final ? client_final_token_ : std::string());
  if (scan.login_ack || scan.error || server_token_final) {
    client_final_token_.clear();
  }
  if (scan.login_ack || scan.error) {
    kerberos_ = Kerberos::Done;
    scanning_login_ = false;
  }
  if (payload.empty()) {
    return std::nullopt;
  }
  return forward(Direction::ServerToClient,
                 makeTdsMessage(kTdsTabularResult, payload, kHandshakePacketSize, server_spid_));
}

std::string TlsBridge::channelBinding(size_t leg) const {
  if (terminate_ == nullptr || terminate_->channel_binding == ChannelBinding::None) {
    return {};
  }
  const Leg& l = leg == kClient ? down_ : up_;
  if (!l.handshake_done) {
    return {}; // No TLS on this leg (or not for the login): nothing to bind to.
  }
  bssl::UniquePtr<X509> peer;
  X509* cert = nullptr;
  if (leg == kClient) {
    cert = SSL_get_certificate(l.ssl.get());
  } else {
    peer.reset(SSL_get_peer_certificate(l.ssl.get()));
    cert = peer.get();
  }
  if (cert == nullptr) {
    return {};
  }
  return "tls-server-end-point:" + tlsServerEndPoint(cert);
}

std::optional<BridgeError> TlsBridge::forward(Direction d, std::string_view bytes) {
  const size_t to = index(other(d)); // The leg the bytes leave on.
  if (to == kServer && !server_ready_) {
    if (pending_to_server_.size() + bytes.size() > kMaxPendingToServer) {
      return protocolError("too much client data before the server's leg was ready");
    }
    pending_to_server_.append(bytes);
    return std::nullopt;
  }
  std::string& out = forwardOutput(d);
  app_sent_[to] = true;
  switch (leg_mode_[to]) {
  case EncryptionMode::Unknown:
  case EncryptionMode::None:
    out += bytes;
    return std::nullopt;
  case EncryptionMode::Full:
    return encrypt(to, bytes, out);
  case EncryptionMode::LoginOnly:
    break;
  }
  // Login-only: the client side only ever receives plain TDS. Toward the
  // server only the first TDS packet of LOGIN7 is encrypted (MS-TDS); a long
  // login, e.g. with a Kerberos ticket, continues in plain packets.
  if (to == kClient || server_first_packet_sent_) {
    out += bytes;
    return std::nullopt;
  }
  if (bytes.size() < kTdsHeaderSize) {
    return protocolError("partial TDS packet for the server");
  }
  const size_t first = (static_cast<uint8_t>(bytes[2]) << 8) | static_cast<uint8_t>(bytes[3]);
  if (first < kTdsHeaderSize || first > bytes.size()) {
    return protocolError("partial TDS packet for the server");
  }
  server_first_packet_sent_ = true;
  if (auto error = encrypt(to, bytes.substr(0, first), out)) {
    return error;
  }
  out += bytes.substr(first);
  return std::nullopt;
}

std::optional<BridgeError> TlsBridge::encrypt(size_t to, std::string_view bytes,
                                              std::string& out) {
  Leg& leg = to == kServer ? up_ : down_;
  if (!leg.handshake_done) {
    return protocolError(std::format("data for the {} before its TLS handshake finished",
                                     to == kServer ? "server" : "client"));
  }
  ERR_clear_error();
  while (!bytes.empty()) {
    const int n = SSL_write(leg.ssl.get(), bytes.data(),
                            static_cast<int>(std::min<size_t>(bytes.size(), INT_MAX)));
    if (n <= 0) {
      return tlsError(sslError(std::format("TLS write to the {} failed",
                                           to == kServer ? "server" : "client")));
    }
    bytes.remove_prefix(static_cast<size_t>(n));
  }
  out += drainTls(leg);
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

void TlsBridge::setMars(size_t leg, bool enabled) {
  wire_[leg].setMarsEnabled(enabled);
  plain_[leg].setMarsEnabled(enabled);
}

void TlsBridge::setMaxPacketSize(size_t size) {
  for (auto* splitters : {&wire_, &plain_}) {
    for (StreamSplitter& s : *splitters) {
      s.setMaxTdsPacketSize(size);
    }
  }
}

} // namespace MssqlProxy
