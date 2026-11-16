#pragma once

// Follows one TDS 7.x connection in both directions: splits each direction into
// units, reads the PRELOGIN exchange to learn the encryption mode, and checks
// that every later unit fits that mode. Observe-only: it never changes bytes.
// No Envoy dependency.
//
// Encryption modes, from the server's PRELOGIN response:
// - None: no TLS at all; plain TDS throughout.
// - LoginOnly (server ENCRYPTION=OFF): TLS handshake in PRELOGIN packets, LOGIN7
//   as raw TLS records, then plain TDS again in both directions.
// - Full (server ENCRYPTION=ON/REQ): TLS handshake in PRELOGIN packets, then
//   raw TLS records only.
// A connection that doesn't open with a client PRELOGIN (e.g. a pre-7.1 client)
// is not parsed at all: the tracker goes passive and passes everything.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "tds.h"

namespace MssqlProxy {

enum class EncryptionMode { Unknown, None, LoginOnly, Full };
const char* encryptionModeName(EncryptionMode mode);

enum class Direction { ClientToServer = 0, ServerToClient = 1 };

struct DirectionStats {
  uint64_t tds_packets = 0;
  uint64_t tds_messages = 0; // TDS packets with EOM set.
  uint64_t tls_records = 0;
  uint64_t smp_packets = 0;
};

class ConnectionTracker {
public:
  ConnectionTracker();
  ConnectionTracker(const ConnectionTracker&) = delete;
  ConnectionTracker& operator=(const ConnectionTracker&) = delete;

  // Feed the bytes seen in one direction, in the order they were seen. Returns
  // an error message when the stream is malformed or breaks the protocol; the
  // caller should close the connection.
  std::optional<std::string> onClientData(std::string_view data) {
    return feed(Direction::ClientToServer, data);
  }
  std::optional<std::string> onServerData(std::string_view data) {
    return feed(Direction::ServerToClient, data);
  }

  // False once the connection turned out not to be a TDS 7.x conversation.
  bool parsing() const { return !passive_; }
  EncryptionMode encryptionMode() const { return mode_; }
  bool marsEnabled() const { return mars_; }
  // Packet size the login negotiated, when the login response was visible
  // (encryption none or login-only); TDS packets above it are then rejected.
  std::optional<uint32_t> packetSize() const { return packet_size_; }
  const DirectionStats& stats(Direction d) const { return stats_[index(d)]; }

private:
  // Where each direction is in the connection.
  enum class Stage {
    Prelogin,  // Before (client) or awaiting (server) the PRELOGIN exchange.
    Handshake, // TLS handshake carried in PRELOGIN packets.
    Tls,       // Raw TLS records.
    Plain,     // Plain TDS after the PRELOGIN exchange.
  };

  class Sink : public UnitSink {
  public:
    Sink(ConnectionTracker& tracker, Direction d) : tracker_(tracker), direction_(d) {}
    std::optional<std::string> onUnit(const Unit& unit) override {
      return tracker_.onUnit(direction_, unit);
    }

  private:
    ConnectionTracker& tracker_;
    Direction direction_;
  };

  static size_t index(Direction d) { return static_cast<size_t>(d); }

  std::optional<std::string> feed(Direction d, std::string_view data);
  std::optional<std::string> onUnit(Direction d, const Unit& unit);
  std::optional<std::string> onPreloginUnit(Direction d, const Unit& unit);
  std::optional<std::string> onPreloginMessage(Direction d, std::string_view payload);
  std::optional<std::string> onLaterUnit(Direction d, const Unit& unit);
  std::optional<std::string> onPlainServerUnit(const Unit& unit);

  std::array<StreamSplitter, 2> splitters_;
  std::array<Sink, 2> sinks_;
  std::array<Stage, 2> stage_{Stage::Prelogin, Stage::Prelogin};
  std::array<DirectionStats, 2> stats_{};
  std::string prelogin_payload_; // PRELOGIN message being assembled.
  std::optional<PreloginOptions> client_prelogin_;
  EncryptionMode mode_ = EncryptionMode::Unknown;
  bool mars_ = false;
  bool passive_ = false;
  // Scanning the server's plain login messages for LOGINACK and the packet size.
  bool scanning_login_ = true;
  size_t login_messages_scanned_ = 0;
  std::string login_message_; // Server message being assembled while scanning.
  std::optional<uint32_t> packet_size_;
};

} // namespace MssqlProxy
