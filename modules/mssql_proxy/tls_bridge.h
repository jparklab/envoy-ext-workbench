#pragma once

// Terminates the TLS of a TDS 7.x connection on both legs, so the proxy sees
// every message in plain text: toward the client it is the TLS server (with
// its own certificate), toward the SQL Server it is the TLS client. No Envoy
// dependency: bytes in, bytes out.
//
// Two ways to open a connection:
// - Forwarded PRELOGIN (default): the client's PRELOGIN goes to the server and
//   the server's answer back to the client, apart from the client-certificate
//   bit, which is cleared (a certificate login can't cross a terminating
//   proxy). Both legs end up in the same encryption mode.
// - Local PRELOGIN (answer_prelogin): the bridge answers the client's PRELOGIN
//   itself, runs the client's TLS handshake and reads its LOGIN7 before any
//   byte goes to the server, so the caller can pick the server from LOGIN7.
//   Only then does it send the client's PRELOGIN upstream (asking for at least
//   login encryption, even for a client that can't encrypt), check that the
//   server's answer fits what the client was told, and forward the LOGIN7.
//   The legs may then differ in encryption mode.
//
// Encryption modes, per leg:
// - None: plain TDS throughout.
// - LoginOnly: TLS handshake inside PRELOGIN packets; LOGIN7 travels encrypted
//   from the client side, then the leg is plain TDS.
// - Full: TLS handshake inside PRELOGIN packets, then only TLS records.
// Every TDS (or MARS SMP) unit is validated and forwarded whole, re-encoded for
// the leg it leaves on, whatever its type. A connection that doesn't open with
// a client PRELOGIN is passed through untouched, as in ConnectionTracker.
//
// The login is followed in a LoginAuth (auth.h): LOGIN7 and the client's SSPI
// messages are held until complete and checked against its policy before they
// go on; a refused login is answered with ERROR 18456 and never reaches the
// server.
//
// Kerberos terminate (auth.terminate): the bridge itself authenticates an
// integrated login. The client's token goes to the proxy's acceptor (rounds
// with the client answered locally); once the client is accepted and allowed,
// the server's leg is opened and the client's LOGIN7 goes on carrying the
// proxy's own token for the server instead of the client's. The server's
// login messages are held until whole: its SSPI tokens go to the proxy's
// initiator (rounds answered locally), and the message with LOGINACK reaches
// the client only once the server has proved itself (mutual authentication),
// with the proxy's last token for the client in place of the server's. GSS
// steps may block on the KDC, so the bridge hands them out (takeWork) and
// waits for resume.

#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "auth.h"
#include "login7.h"
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

struct BridgeOptions {
  // Answer the client's PRELOGIN locally and hold everything for the server
  // until the client's LOGIN7 has been read (see above).
  bool answer_prelogin = false;
  // Login policy; null means the defaults (allow everything).
  std::shared_ptr<const AuthSettings> auth;
};

struct BridgeError {
  enum class Kind {
    Protocol,     // Malformed TDS or a protocol violation.
    Tls,          // TLS handshake or record failure on either leg.
    Incompatible, // The server's PRELOGIN answer contradicts the local one.
    Denied,       // The proxy refused the login: send to_client, then close.
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
  TlsBridge(std::shared_ptr<const TlsContexts> contexts, BridgeOptions options = {});
  TlsBridge(const TlsBridge&) = delete;
  TlsBridge& operator=(const TlsBridge&) = delete;

  // Feed the bytes received from one side, in order. Appends what to send on
  // to out. On error the connection should be closed; out may then hold
  // partial output, which should be dropped, except for Denied, whose
  // to_client carries the refusal and should be sent before closing.
  std::optional<BridgeError> onClientData(std::string_view data, BridgeOutput& out) {
    return feed(Direction::ClientToServer, data, out);
  }
  std::optional<BridgeError> onServerData(std::string_view data, BridgeOutput& out) {
    return feed(Direction::ServerToClient, data, out);
  }

  // False once the connection turned out not to be a TDS 7.x conversation.
  bool parsing() const { return !passive_; }
  // Encryption mode of the client's leg, and of the server's.
  EncryptionMode encryptionMode() const { return leg_mode_[kClient]; }
  EncryptionMode serverEncryptionMode() const { return leg_mode_[kServer]; }
  bool marsEnabled() const { return mars_; }
  // True once every TLS handshake the legs need is done (both legs encrypted).
  bool tlsEstablished() const { return down_.handshake_done && up_.handshake_done; }
  // The client asked for a certificate login, which was turned off.
  bool clientCertCleared() const { return client_cert_cleared_; }
  std::optional<uint32_t> packetSize() const { return packet_size_; }
  // The client's LOGIN7, once read (decrypted when sent over TLS).
  const std::optional<Login7>& login() const { return login_; }
  // True once anything has been sent toward the server. With answer_prelogin
  // this happens in the call that reads LOGIN7: route before sending it on.
  bool upstreamStarted() const { return upstream_started_; }
  // How the client logs in, who it claims to be, and the outcome.
  const LoginAuth& auth() const { return auth_; }

  // Kerberos terminate: a GSS step is pending. Take it with takeWork, run it
  // on any thread (it may block on the KDC), then call resume on this
  // bridge's thread. Data fed in the meantime is held and processed by resume.
  bool waiting() const { return waiting_; }
  std::function<void()> takeWork() { return std::exchange(work_, nullptr); }
  // Continues after the step ran; output and errors as for onClientData.
  std::optional<BridgeError> resume(BridgeOutput& out);
  // Kerberos terminate: the SPN to log in to the server with, e.g. the routed
  // cluster's (default: auth.terminate's spn). Set before the server's leg
  // is ready.
  void setUpstreamSpn(std::string spn) { upstream_spn_ = std::move(spn); }

private:
  enum class Stage { Prelogin, Handshake, Tls, Plain };

  // Kerberos terminate, in order. Accepting, Initiating and Verifying wait for
  // a GSS step.
  enum class Kerberos {
    Off,         // Not terminating (or not yet).
    Accepting,   // The client's token is with the acceptor.
    AwaitClient, // The client owes the acceptor another token.
    Accepted,    // Waiting for the server's leg.
    Initiating,  // Making the proxy's token for the server.
    AwaitServer, // LOGIN7 (or a token) sent; the server's answer is due.
    Verifying,   // The server's token is with the initiator.
    Done,        // The server's verdict reached the client.
  };

  // Legs are indexed by the direction of the data they receive.
  static constexpr size_t kClient = 0; // Direction::ClientToServer
  static constexpr size_t kServer = 1; // Direction::ServerToClient

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
  std::optional<BridgeError> onClientPrelogin(std::string& payload);
  std::optional<BridgeError> onServerPrelogin(const std::string& payload);
  std::optional<BridgeError> startLeg(Direction from);
  std::optional<BridgeError> serverReady();
  std::optional<BridgeError> driveHandshake(Direction from);
  std::optional<BridgeError> decrypt(Direction from, std::string_view record);
  std::optional<BridgeError> onPlainUnit(Direction d, const Unit& unit);
  std::optional<BridgeError> readLogin7(const Unit& unit);
  std::optional<BridgeError> readClientSspi(const Unit& unit);
  BridgeError deny(const Denial& denial);
  std::optional<BridgeError> scanLoginMessage(const Unit& unit);
  void startAccept(std::string_view token);
  std::optional<BridgeError> afterAccept(KerberosExchange::Step step);
  void maybeStartInitiate();
  void startInitiate(std::string_view token);
  std::optional<BridgeError> afterInitiate(KerberosExchange::Step step);
  std::optional<BridgeError> onServerLoginUnit(const Unit& unit);
  std::optional<BridgeError> finishServerMessage(const std::string& message,
                                                 const LoginResponseScan& scan);
  // Channel binding application data for a leg, or empty.
  std::string channelBinding(size_t leg) const;
  // Sends whole TDS packets on the other leg, encrypted as that leg needs.
  // Under login-only toward the server, MS-TDS: only the first TDS packet sent
  // after the handshake (the start of LOGIN7) is encrypted, the rest plain.
  std::optional<BridgeError> forward(Direction d, std::string_view bytes);
  std::optional<BridgeError> encrypt(size_t to, std::string_view bytes, std::string& out);
  std::string drainTls(Leg& leg);
  void setMars(size_t leg, bool enabled);
  void setMaxPacketSize(size_t size);

  std::shared_ptr<const TlsContexts> contexts_;
  BridgeOptions options_;
  // TLS session with the client (we are the server) and with the SQL Server
  // (we are the client).
  Leg down_;
  Leg up_;

  std::array<StreamSplitter, 2> wire_;
  std::array<StreamSplitter, 2> plain_; // Decrypted streams.
  std::array<Sink, 2> wire_sinks_;
  std::array<Sink, 2> plain_sinks_;
  std::array<Stage, 2> stage_{Stage::Prelogin, Stage::Prelogin};
  std::array<EncryptionMode, 2> leg_mode_{EncryptionMode::Unknown, EncryptionMode::Unknown};
  // Application data (after PRELOGIN and handshake) sent on each leg: under
  // login-only this marks where the leg's input leaves TLS.
  std::array<bool, 2> app_sent_{false, false};
  // Under login-only, the first packet toward the server has gone encrypted.
  bool server_first_packet_sent_ = false;

  BridgeOutput* out_ = nullptr;      // Output of the call in progress.
  std::optional<BridgeError> error_; // Error raised inside a sink.
  std::string client_raw_;           // Client bytes until its PRELOGIN, for passthrough.
  std::string prelogin_payload_;     // PRELOGIN message being assembled.
  std::optional<PreloginOptions> client_prelogin_;
  std::string upstream_prelogin_; // The PRELOGIN message for the server.
  // Its ENCRYPTION option (the client's, raised to Off from NotSupported
  // under answer_prelogin).
  PreloginEncryption upstream_encryption_ = PreloginEncryption::Off;
  bool upstream_started_ = false;
  bool server_ready_ = false;     // The server's leg can carry application data.
  std::string pending_to_server_; // Plain text waiting for the server's leg.

  bool mars_ = false;
  bool passive_ = false;
  bool client_cert_cleared_ = false;

  std::string login7_message_; // LOGIN7 being assembled (payload).
  std::string login7_wire_;    // Its packets, held until the policy allows them.
  std::optional<Login7> login_;
  std::string sspi_message_; // A client SSPI message being assembled, likewise.
  std::string sspi_wire_;
  LoginAuth auth_;

  // Scanning the server's login messages for LOGINACK and the packet size.
  bool scanning_login_ = true;
  size_t login_messages_scanned_ = 0;
  std::string login_message_;
  std::optional<uint32_t> packet_size_;

  // Kerberos terminate.
  const KerberosTerminate* terminate_ = nullptr; // In options_.auth; null when off.
  Kerberos kerberos_ = Kerberos::Off;
  std::shared_ptr<KerberosExchange> exchange_;
  std::shared_ptr<KerberosExchange::Step> step_; // The pending step's result.
  std::function<void()> work_;                   // The pending step, until taken.
  bool waiting_ = false;
  std::array<std::string, 2> held_input_; // Data fed while waiting.
  std::string login7_payload_;            // The client's LOGIN7, for the server.
  std::string client_final_token_;        // The proxy's last token, sent with LOGINACK.
  std::string upstream_spn_;
  bool upstream_complete_ = false; // The server has authenticated itself.
  std::string server_message_;     // A server login message being assembled.
  uint16_t server_spid_ = 0;
  std::string held_message_; // A server message whose SSPI token is being checked.
  LoginResponseScan held_scan_;
};

} // namespace MssqlProxy
