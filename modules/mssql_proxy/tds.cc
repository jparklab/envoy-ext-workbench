#include "tds.h"

#include <format>

namespace MssqlProxy {

const char* unitKindName(UnitKind kind) {
  switch (kind) {
  case UnitKind::TdsPacket:
    return "TDS packet";
  case UnitKind::TlsRecord:
    return "TLS record";
  case UnitKind::SmpPacket:
    return "SMP packet";
  }
  return "unknown";
}

std::string_view Unit::payload() const {
  switch (kind) {
  case UnitKind::TdsPacket:
    return bytes.substr(kTdsHeaderSize);
  case UnitKind::TlsRecord:
    return bytes.substr(kTlsHeaderSize);
  case UnitKind::SmpPacket:
    return bytes.substr(kSmpHeaderSize);
  }
  return {};
}

namespace {

uint16_t readBe16(std::string_view b, size_t at) {
  return static_cast<uint16_t>((static_cast<uint8_t>(b[at]) << 8) | static_cast<uint8_t>(b[at + 1]));
}

uint32_t readLe32(std::string_view b, size_t at) {
  return static_cast<uint32_t>(static_cast<uint8_t>(b[at])) |
         static_cast<uint32_t>(static_cast<uint8_t>(b[at + 1])) << 8 |
         static_cast<uint32_t>(static_cast<uint8_t>(b[at + 2])) << 16 |
         static_cast<uint32_t>(static_cast<uint8_t>(b[at + 3])) << 24;
}

bool isTlsContentType(uint8_t b) { return b >= 0x14 && b <= 0x17; }

struct Header {
  UnitKind kind;
  uint8_t type;
  bool eom;
  size_t size; // Whole unit, header included.
};

// Returns nullopt when the header is incomplete; sets error when it is invalid.
std::optional<Header> peekHeader(std::string_view b, bool mars, std::string& error) {
  const uint8_t first = static_cast<uint8_t>(b[0]);
  if (isTlsContentType(first)) {
    if (b.size() < kTlsHeaderSize) {
      return std::nullopt;
    }
    if (b[1] != 0x03) {
      error = std::format("TLS record with unexpected version major 0x{:02x}",
                          static_cast<uint8_t>(b[1]));
      return std::nullopt;
    }
    const size_t len = readBe16(b, 3);
    if (len == 0 || len > kTlsMaxRecordPayload) {
      error = std::format("TLS record payload length {} out of range", len);
      return std::nullopt;
    }
    return Header{UnitKind::TlsRecord, first, false, kTlsHeaderSize + len};
  }
  if (mars && first == kSmpId) {
    if (b.size() < kSmpHeaderSize) {
      return std::nullopt;
    }
    const size_t len = readLe32(b, 4);
    if (len < kSmpHeaderSize || len > kSmpHeaderSize + kTdsMaxPacketSize) {
      error = std::format("SMP packet length {} out of range", len);
      return std::nullopt;
    }
    return Header{UnitKind::SmpPacket, static_cast<uint8_t>(b[1]), false, len};
  }
  if (b.size() < kTdsHeaderSize) {
    return std::nullopt;
  }
  const size_t len = readBe16(b, 2);
  if (len < kTdsHeaderSize || len > kTdsMaxPacketSize) {
    error = std::format("TDS packet (type 0x{:02x}) length {} out of range", first, len);
    return std::nullopt;
  }
  return Header{UnitKind::TdsPacket, first, (static_cast<uint8_t>(b[1]) & kTdsStatusEom) != 0,
                len};
}

} // namespace

std::optional<std::string> StreamSplitter::feed(std::string_view data, UnitSink& sink) {
  if (failed_) {
    return "splitter already failed";
  }
  buffer_.append(data);
  size_t pos = 0;
  std::optional<std::string> result;
  while (pos < buffer_.size()) {
    const std::string_view rest = std::string_view(buffer_).substr(pos);
    std::string error;
    const std::optional<Header> h = peekHeader(rest, mars_enabled_, error);
    if (!error.empty()) {
      result = std::move(error);
      break;
    }
    if (!h || rest.size() < h->size) {
      break; // Incomplete header or unit: wait for more bytes.
    }
    const Unit unit{h->kind, h->type, h->eom, rest.substr(0, h->size)};
    if (auto stop = sink.onUnit(unit)) {
      result = std::move(stop);
      break;
    }
    pos += h->size;
  }
  if (result) {
    failed_ = true;
    buffer_.clear();
    return result;
  }
  buffer_.erase(0, pos);
  return std::nullopt;
}

std::optional<PreloginOptions> parsePrelogin(std::string_view payload, std::string& error) {
  // Option table: (token:1, offset:2 BE, length:2 BE)*, terminated by 0xFF.
  // Offsets are relative to the start of the payload.
  constexpr uint8_t kTerminator = 0xff;
  constexpr uint8_t kEncryption = 0x01;
  constexpr uint8_t kMars = 0x04;

  PreloginOptions options;
  size_t pos = 0;
  while (true) {
    if (pos >= payload.size()) {
      error = "PRELOGIN option table has no terminator";
      return std::nullopt;
    }
    const uint8_t token = static_cast<uint8_t>(payload[pos]);
    if (token == kTerminator) {
      break;
    }
    if (payload.size() - pos < 5) {
      error = "PRELOGIN option entry truncated";
      return std::nullopt;
    }
    const size_t offset = readBe16(payload, pos + 1);
    const size_t length = readBe16(payload, pos + 3);
    if (offset > payload.size() || length > payload.size() - offset) {
      error = std::format("PRELOGIN option 0x{:02x} data out of bounds", token);
      return std::nullopt;
    }
    const std::string_view value = payload.substr(offset, length);
    if (token == kEncryption) {
      if (length != 1) {
        error = std::format("PRELOGIN ENCRYPTION length {}", length);
        return std::nullopt;
      }
      const uint8_t v = static_cast<uint8_t>(value[0]) & 0x7f; // Drop the client-cert bit.
      if (v > static_cast<uint8_t>(PreloginEncryption::Required)) {
        error = std::format("PRELOGIN ENCRYPTION value 0x{:02x}", v);
        return std::nullopt;
      }
      options.encryption = static_cast<PreloginEncryption>(v);
    } else if (token == kMars && length >= 1) {
      options.mars = value[0] != 0;
    }
    pos += 5;
  }
  return options;
}

} // namespace MssqlProxy
