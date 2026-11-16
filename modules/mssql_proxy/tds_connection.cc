#include "tds_connection.h"

#include <format>

namespace MssqlProxy {

const char* encryptionModeName(EncryptionMode mode) {
  switch (mode) {
  case EncryptionMode::Unknown:
    return "unknown";
  case EncryptionMode::None:
    return "none";
  case EncryptionMode::LoginOnly:
    return "login-only";
  case EncryptionMode::Full:
    return "full";
  }
  return "unknown";
}

namespace {

const char* directionName(Direction d) {
  return d == Direction::ClientToServer ? "client" : "server";
}

// A PRELOGIN message is a handful of options; anything near a full packet is
// already suspicious.
constexpr size_t kMaxPreloginMessage = kTdsMaxPacketSize;

} // namespace

ConnectionTracker::ConnectionTracker()
    : sinks_{Sink(*this, Direction::ClientToServer), Sink(*this, Direction::ServerToClient)} {}

std::optional<std::string> ConnectionTracker::feed(Direction d, std::string_view data) {
  if (passive_ || data.empty()) {
    return std::nullopt;
  }
  if (auto error = splitters_[index(d)].feed(data, sinks_[index(d)])) {
    if (passive_) {
      return std::nullopt; // Not TDS 7.x after all: stopped on purpose.
    }
    return std::format("{}: {}", directionName(d), *error);
  }
  return std::nullopt;
}

std::optional<std::string> ConnectionTracker::onUnit(Direction d, const Unit& unit) {
  DirectionStats& s = stats_[index(d)];
  switch (unit.kind) {
  case UnitKind::TdsPacket:
    s.tds_packets++;
    s.tds_messages += unit.eom ? 1 : 0;
    break;
  case UnitKind::TlsRecord:
    s.tls_records++;
    break;
  case UnitKind::SmpPacket:
    s.smp_packets++;
    break;
  }
  if (stage_[index(d)] == Stage::Prelogin) {
    return onPreloginUnit(d, unit);
  }
  return onLaterUnit(d, unit);
}

std::optional<std::string> ConnectionTracker::onPreloginUnit(Direction d, const Unit& unit) {
  const bool client = d == Direction::ClientToServer;
  if (client && client_prelogin_) {
    return "data before the server's PRELOGIN response";
  }
  if (!client && !client_prelogin_) {
    return "data before the client's PRELOGIN";
  }
  const uint8_t want = client ? kTdsPrelogin : kTdsTabularResult;
  if (unit.kind != UnitKind::TdsPacket || unit.type != want) {
    if (client && prelogin_payload_.empty()) {
      // Doesn't open with PRELOGIN: not a TDS 7.x conversation we understand.
      // Stop parsing and let it through untouched.
      passive_ = true;
      return "passive";
    }
    return std::format("expected a PRELOGIN {}, got {} type 0x{:02x}",
                       client ? "message" : "response", unitKindName(unit.kind), unit.type);
  }
  if (prelogin_payload_.size() + unit.payload().size() > kMaxPreloginMessage) {
    return "PRELOGIN message too large";
  }
  prelogin_payload_.append(unit.payload());
  if (!unit.eom) {
    return std::nullopt;
  }
  std::string payload = std::move(prelogin_payload_);
  prelogin_payload_.clear();
  return onPreloginMessage(d, payload);
}

std::optional<std::string> ConnectionTracker::onPreloginMessage(Direction d,
                                                                std::string_view payload) {
  std::string error;
  std::optional<PreloginOptions> options = parsePrelogin(payload, error);
  if (!options) {
    return error;
  }
  if (d == Direction::ClientToServer) {
    client_prelogin_ = *options;
    return std::nullopt;
  }

  const auto client = client_prelogin_->encryption.value_or(PreloginEncryption::Off);
  const auto server = options->encryption.value_or(PreloginEncryption::Off);
  if (client == PreloginEncryption::NotSupported || server == PreloginEncryption::NotSupported) {
    // Neither side encrypts (if the server requires it, it closes the connection).
    mode_ = EncryptionMode::None;
  } else if (server == PreloginEncryption::Off) {
    mode_ = EncryptionMode::LoginOnly;
  } else {
    mode_ = EncryptionMode::Full;
  }
  mars_ = client_prelogin_->mars.value_or(false) && options->mars.value_or(false);
  for (StreamSplitter& s : splitters_) {
    s.setMarsEnabled(mars_);
  }
  const Stage next = mode_ == EncryptionMode::None ? Stage::Plain : Stage::Handshake;
  stage_ = {next, next};
  return std::nullopt;
}

std::optional<std::string> ConnectionTracker::onLaterUnit(Direction d, const Unit& unit) {
  Stage& stage = stage_[index(d)];
  const Stage other = stage_[1 - index(d)];
  const bool client = d == Direction::ClientToServer;
  const bool tls = unit.kind == UnitKind::TlsRecord;
  const bool handshake_packet = unit.kind == UnitKind::TdsPacket && unit.type == kTdsPrelogin;

  switch (stage) {
  case Stage::Prelogin:
    break; // Handled by onPreloginUnit.

  case Stage::Handshake:
    if (handshake_packet) {
      return std::nullopt;
    }
    if (tls) {
      // Under login-only the server never sends raw TLS: it answers the
      // client's encrypted LOGIN7 in plain TDS.
      if (!client && mode_ == EncryptionMode::LoginOnly) {
        return "raw TLS from the server under login-only encryption";
      }
      stage = Stage::Tls;
      return std::nullopt;
    }
    if (!client && mode_ == EncryptionMode::LoginOnly && other != Stage::Handshake) {
      stage = Stage::Plain; // The login response, after the client's encrypted LOGIN7.
      return std::nullopt;
    }
    return std::format("plain {} type 0x{:02x} during the TLS handshake",
                       unitKindName(unit.kind), unit.type);

  case Stage::Tls:
    if (tls) {
      return std::nullopt;
    }
    if (client && mode_ == EncryptionMode::LoginOnly && other == Stage::Plain) {
      stage = Stage::Plain; // Back to plain TDS once the login is answered.
      return std::nullopt;
    }
    return std::format("plain {} type 0x{:02x} after TLS under {} encryption",
                       unitKindName(unit.kind), unit.type, encryptionModeName(mode_));

  case Stage::Plain:
    if (tls) {
      return std::format("raw TLS record in plain TDS under {} encryption",
                         encryptionModeName(mode_));
    }
    return std::nullopt;
  }
  return std::nullopt;
}

} // namespace MssqlProxy
