#include "tds.h"

#include <algorithm>
#include <format>
#include <utility>
#include <vector>

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
std::optional<Header> peekHeader(std::string_view b, bool mars, size_t max_tds,
                                 std::string& error) {
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
    if (len < kSmpHeaderSize || len > kSmpHeaderSize + max_tds) {
      error = std::format("SMP packet length {} out of range", len);
      return std::nullopt;
    }
    return Header{UnitKind::SmpPacket, static_cast<uint8_t>(b[1]), false, len};
  }
  if (b.size() < kTdsHeaderSize) {
    return std::nullopt;
  }
  const size_t len = readBe16(b, 2);
  if (len < kTdsHeaderSize || len > max_tds) {
    error = std::format("TDS packet (type 0x{:02x}) length {} out of range (max {})", first, len,
                        max_tds);
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
    const std::optional<Header> h = peekHeader(rest, mars_enabled_, max_tds_packet_, error);
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
  constexpr uint8_t kInstOpt = 0x02;
  constexpr uint8_t kThreadId = 0x03;
  constexpr uint8_t kMars = 0x04;
  constexpr uint8_t kFedAuthRequired = 0x06;
  constexpr uint8_t kNonce = 0x07;

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
      options.client_cert = (static_cast<uint8_t>(value[0]) & 0x80) != 0;
      options.encryption_offset = offset;
      if (v > static_cast<uint8_t>(PreloginEncryption::Required)) {
        error = std::format("PRELOGIN ENCRYPTION value 0x{:02x}", v);
        return std::nullopt;
      }
      options.encryption = static_cast<PreloginEncryption>(v);
    } else if (token == kMars && length >= 1) {
      options.mars = value[0] != 0;
    } else if (token == kInstOpt) {
      options.instance = std::string(value);
    } else if (token == kThreadId) {
      options.thread_id = true;
    } else if (token == kFedAuthRequired && length >= 1) {
      options.fedauth_required = static_cast<uint8_t>(value[0]);
    } else if (token == kNonce) {
      options.nonce = true;
    }
    pos += 5;
  }
  return options;
}

std::string buildPreloginResponse(const PreloginOptions& client, PreloginEncryption encryption,
                                  std::string_view version) {
  std::vector<std::pair<uint8_t, std::string>> options;
  options.emplace_back(0x00, std::string(version));
  options.emplace_back(0x01, std::string(1, static_cast<char>(encryption)));
  if (client.instance) {
    options.emplace_back(0x02, std::string(1, '\0'));
  }
  if (client.thread_id) {
    options.emplace_back(0x03, std::string());
  }
  if (client.mars) {
    options.emplace_back(0x04, std::string(1, static_cast<char>(*client.mars ? 1 : 0)));
  }
  // Option table, then the values in the same order.
  const size_t table = options.size() * 5 + 1;
  std::string head;
  std::string data;
  for (const auto& [token, value] : options) {
    const size_t offset = table + data.size();
    head.push_back(static_cast<char>(token));
    head.push_back(static_cast<char>(offset >> 8));
    head.push_back(static_cast<char>(offset & 0xff));
    head.push_back(static_cast<char>(value.size() >> 8));
    head.push_back(static_cast<char>(value.size() & 0xff));
    data += value;
  }
  head.push_back(static_cast<char>(0xff));
  return head + data;
}

std::string makeTdsMessage(uint8_t type, std::string_view payload, size_t max_packet) {
  const size_t chunk = max_packet - kTdsHeaderSize;
  std::string out;
  uint8_t packet_id = 1;
  size_t pos = 0;
  do {
    const size_t n = std::min(chunk, payload.size() - pos);
    const size_t len = kTdsHeaderSize + n;
    const bool last = pos + n == payload.size();
    const char header[kTdsHeaderSize] = {
        static_cast<char>(type),
        static_cast<char>(last ? kTdsStatusEom : 0),
        static_cast<char>(len >> 8),
        static_cast<char>(len & 0xff),
        0, // SPID
        0,
        static_cast<char>(packet_id++),
        0, // Window
    };
    out.append(header, kTdsHeaderSize);
    out.append(payload.substr(pos, n));
    pos += n;
  } while (pos < payload.size());
  return out;
}

namespace {

uint16_t readLe16(std::string_view b, size_t at) {
  return static_cast<uint16_t>(static_cast<uint8_t>(b[at]) | (static_cast<uint8_t>(b[at + 1]) << 8));
}

// ENVCHANGE data: Type BYTE, then for type 4 (packet size) NewValue and
// OldValue as B_VARCHAR (char count BYTE, UTF-16LE chars) holding decimal text.
std::optional<std::string> parseEnvChange(std::string_view data, LoginResponseScan& scan) {
  constexpr uint8_t kEnvPacketSize = 4;
  if (data.empty()) {
    return "empty ENVCHANGE";
  }
  if (static_cast<uint8_t>(data[0]) != kEnvPacketSize) {
    return std::nullopt;
  }
  if (data.size() < 2) {
    return "ENVCHANGE packet size truncated";
  }
  const size_t chars = static_cast<uint8_t>(data[1]);
  if (chars == 0 || chars > 5 || data.size() < 2 + 2 * chars) {
    return std::format("ENVCHANGE packet size value of {} chars", chars);
  }
  uint32_t value = 0;
  for (size_t i = 0; i < chars; ++i) {
    const uint16_t c = readLe16(data, 2 + 2 * i);
    if (c < '0' || c > '9') {
      return "ENVCHANGE packet size is not a number";
    }
    value = value * 10 + (c - '0');
  }
  if (value < kTdsMinPacketSize || value > kTdsMaxPacketSize) {
    return std::format("ENVCHANGE packet size {} out of range", value);
  }
  scan.packet_size = value;
  return std::nullopt;
}

} // namespace

std::optional<LoginResponseScan> scanLoginResponse(std::string_view payload, std::string& error) {
  constexpr uint8_t kSspi = 0xed, kError = 0xaa, kInfo = 0xab, kLoginAck = 0xad,
                    kEnvChange = 0xe3, kFeatureExtAck = 0xae, kSessionState = 0xe4,
                    kFedAuthInfo = 0xee, kReturnStatus = 0x79, kDone = 0xfd, kDoneProc = 0xfe,
                    kDoneInProc = 0xff;
  constexpr size_t kDoneSize = 12; // Status, CurCmd, 8-byte row count (TDS 7.2+).

  LoginResponseScan scan;
  size_t pos = 0;
  auto need = [&](size_t n, const char* what) {
    if (payload.size() - pos < n) {
      error = std::format("{} token truncated", what);
      return false;
    }
    return true;
  };
  while (pos < payload.size()) {
    const uint8_t token = static_cast<uint8_t>(payload[pos++]);
    switch (token) {
    case kSspi:
    case kError:
    case kInfo:
    case kLoginAck:
    case kEnvChange: {
      if (!need(2, "USHORT-length")) {
        return std::nullopt;
      }
      const size_t len = readLe16(payload, pos);
      pos += 2;
      if (!need(len, "USHORT-length")) {
        return std::nullopt;
      }
      const std::string_view data = payload.substr(pos, len);
      pos += len;
      if (token == kLoginAck) {
        scan.login_ack = true;
      } else if (token == kEnvChange) {
        if (auto e = parseEnvChange(data, scan)) {
          error = std::move(*e);
          return std::nullopt;
        }
      }
      break;
    }
    case kSessionState:
    case kFedAuthInfo: {
      if (!need(4, "DWORD-length")) {
        return std::nullopt;
      }
      const size_t len = readLe32(payload, pos);
      pos += 4;
      if (!need(len, "DWORD-length")) {
        return std::nullopt;
      }
      pos += len;
      break;
    }
    case kFeatureExtAck:
      // (FeatureId BYTE, FeatureAckDataLen DWORD, data)*, then 0xFF.
      while (true) {
        if (!need(1, "FEATUREEXTACK")) {
          return std::nullopt;
        }
        if (static_cast<uint8_t>(payload[pos++]) == 0xff) {
          break;
        }
        if (!need(4, "FEATUREEXTACK")) {
          return std::nullopt;
        }
        const size_t len = readLe32(payload, pos);
        pos += 4;
        if (!need(len, "FEATUREEXTACK")) {
          return std::nullopt;
        }
        pos += len;
      }
      break;
    case kReturnStatus:
      if (!need(4, "RETURNSTATUS")) {
        return std::nullopt;
      }
      pos += 4;
      break;
    case kDone:
    case kDoneProc:
    case kDoneInProc:
      if (!need(kDoneSize, "DONE")) {
        return std::nullopt;
      }
      pos += kDoneSize;
      break;
    default:
      return scan; // Unknown token: its length can't be derived, stop here.
    }
  }
  scan.fully_scanned = true;
  return scan;
}

} // namespace MssqlProxy
