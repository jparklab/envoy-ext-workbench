#pragma once

// Terminates the TLS of a TDS 7.x connection on both legs, so the proxy sees
// every message in plain text: toward the client it is the TLS server (with
// its own certificate), toward the SQL Server it is the TLS client. No Envoy
// dependency: bytes in, bytes out.
//
// Both legs end up in the same encryption mode, because the PRELOGIN exchange
// is forwarded as is, apart from the client-certificate bit, which is cleared
// (a certificate login can't cross a terminating proxy). Per mode:
// - None: plain TDS throughout; units are validated and forwarded.
// - LoginOnly: each leg runs its own TLS handshake inside PRELOGIN packets;
//   the client's LOGIN7 is decrypted and re-encrypted toward the server; then
//   both legs go back to plain TDS.
// - Full: as LoginOnly, but every later message is decrypted and re-encrypted,
//   whatever its type.
// Only whole TDS (or MARS SMP) units are forwarded, after validation. A
// connection that doesn't open with a client PRELOGIN is passed through
// untouched, as in ConnectionTracker.

#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "tds.h"
#include "tds_connection.h"

namespace MssqlProxy {

struct TlsSettings {
  // Presented to clients: PEM certificate chain (leaf first) and private key.
  std::string cert_pem;
  std::string key_pem;
  // Verify the SQL Server's certificate against upstream_ca_pem: CA
  // certificates, or the server's own certificate (each one is a trust anchor).
  bool upstream_verify = true;
  std::string upstream_ca_pem;
  // Sent as SNI and checked against the server's certificate when set. An IP
  // address is checked against the certificate's IP addresses and not sent.
  std::string upstream_server_name;
};

// TLS contexts shared by every connection of one filter config. Thread-safe.
class TlsContexts {
public:
  static std::shared_ptr<const TlsContexts> create(const TlsSettings& settings,
                                                   std::string& error);

  SSL_CTX* downstream() const { return downstream_.get(); }
  SSL_CTX* upstream() const { return upstream_.get(); }
  const std::string& upstreamServerName() const { return server_name_; }

private:
  bssl::UniquePtr<SSL_CTX> downstream_;
  bssl::UniquePtr<SSL_CTX> upstream_;
  std::string server_name_;
};

struct BridgeError {
  enum class Kind {
    Protocol, // Malformed TDS or a protocol violation.
    Tls,      // TLS handshake or record failure on either leg.
  };
  Kind kind;
  std::string message;
};

// Bytes to send on as the result of one call.
struct BridgeOutput {
  std::string to_client;
  std::string to_server;
};

class TlsBridge {
public:
  explicit TlsBridge(std::shared_ptr<const TlsContexts> contexts);
  TlsBridge(const TlsBridge&) = delete;
  TlsBridge& operator=(const TlsBridge&) = delete;

  // Feed the bytes received from one side, in order. Appends what to send on
  // to out. On error the connection should be closed; out may then hold
  // partial output, which should be dropped.
  std::optional<BridgeError> onClientData(std::string_view data, BridgeOutput& out) {
    return feed(Direction::ClientToServer, data, out);
  }
  std::optional<BridgeError> onServerData(std::string_view data, BridgeOutput& out) {
    return feed(Direction::ServerToClient, data, out);
  }

  // False once the connection turned out not to be a TDS 7.x conversation.
  bool parsing() const { return !passive_; }
  EncryptionMode encryptionMode() const { return mode_; }
  bool marsEnabled() const { return mars_; }
  // True once the TLS handshakes with both the client and the server are done.
  bool tlsEstablished() const { return down_.handshake_done && up_.handshake_done; }
  // The client asked for a certificate login, which was turned off.
  bool clientCertCleared() const { return client_cert_cleared_; }
  std::optional<uint32_t> packetSize() const { return packet_size_; }
  // LOGIN7 messages seen in plain text (decrypted when sent over TLS).
  uint64_t login7Messages() const { return login7_messages_; }

private:
  enum class Stage { Prelogin, Handshake, Tls, Plain };

  // One TLS session, with memory BIOs: rbio holds received TLS bytes, wbio
  // collects TLS bytes to send.
  struct Leg {
    bssl::UniquePtr<SSL> ssl;
    BIO* rbio = nullptr; // Owned by ssl.
    BIO* wbio = nullptr; // Owned by ssl.
    bool handshake_done = false;
  };

  class Sink : public UnitSink {
  public:
    Sink(TlsBridge& bridge, Direction d, bool decrypted)
        : bridge_(bridge), direction_(d), decrypted_(decrypted) {}
    std::optional<std::string> onUnit(const Unit& unit) override;

  private:
    TlsBridge& bridge_;
    Direction direction_;
    bool decrypted_; // Units from the decrypted stream rather than the wire.
  };

  static size_t index(Direction d) { return static_cast<size_t>(d); }
  static Direction other(Direction d) {
    return d == Direction::ClientToServer ? Direction::ServerToClient
                                          : Direction::ClientToServer;
  }
  // The TLS session that receives from (and sends to) this side.
  Leg& legOf(Direction from) { return from == Direction::ClientToServer ? down_ : up_; }
  // Output onward, for data travelling in direction d.
  std::string& forwardOutput(Direction d) {
    return d == Direction::ClientToServer ? out_->to_server : out_->to_client;
  }
  // Output back to the side that sent data travelling in direction d.
  std::string& replyOutput(Direction d) { return forwardOutput(other(d)); }

  std::optional<BridgeError> feed(Direction d, std::string_view data, BridgeOutput& out);
  std::optional<BridgeError> onWireUnit(Direction d, const Unit& unit);
  std::optional<BridgeError> onPreloginUnit(Direction d, const Unit& unit);
  std::optional<BridgeError> onPreloginMessage(Direction d, std::string& payload);
  std::optional<BridgeError> driveHandshake(Direction from);
  std::optional<BridgeError> decrypt(Direction from, std::string_view record);
  std::optional<BridgeError> onPlainUnit(Direction d, const Unit& unit, bool decrypted);
  std::optional<BridgeError> scanLoginMessage(const Unit& unit);
  std::optional<BridgeError> sendEncrypted(Direction d, std::string_view plain);
  std::string drainTls(Leg& leg);
  void setMaxPacketSize(size_t size);

  std::shared_ptr<const TlsContexts> contexts_;
  // TLS session with the client (we are the server) and with the SQL Server
  // (we are the client).
  Leg down_;
  Leg up_;

  std::array<StreamSplitter, 2> wire_;
  std::array<StreamSplitter, 2> plain_; // Decrypted streams.
  std::array<Sink, 2> wire_sinks_;
  std::array<Sink, 2> plain_sinks_;
  std::array<Stage, 2> stage_{Stage::Prelogin, Stage::Prelogin};

  BridgeOutput* out_ = nullptr;      // Output of the call in progress.
  std::optional<BridgeError> error_; // Error raised inside a sink.
  std::string client_raw_;           // Client bytes until its PRELOGIN, for passthrough.
  std::string prelogin_payload_;     // PRELOGIN message being assembled.
  std::optional<PreloginOptions> client_prelogin_;
  std::string pending_to_server_; // Plain text waiting for the server handshake.

  EncryptionMode mode_ = EncryptionMode::Unknown;
  bool mars_ = false;
  bool passive_ = false;
  bool client_cert_cleared_ = false;
  uint64_t login7_messages_ = 0;

  // Scanning the server's login messages for LOGINACK and the packet size.
  bool scanning_login_ = true;
  size_t login_messages_scanned_ = 0;
  std::string login_message_;
  std::optional<uint32_t> packet_size_;
};

} // namespace MssqlProxy
