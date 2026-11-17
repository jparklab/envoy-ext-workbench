#pragma once

// Builders for TDS bytes, shared by the unit tests.

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tds.h"

namespace MssqlProxy {
namespace test {

inline std::string tdsPacket(uint8_t type, bool eom, std::string_view payload) {
  const size_t len = kTdsHeaderSize + payload.size();
  std::string p;
  p.push_back(static_cast<char>(type));
  p.push_back(static_cast<char>(eom ? kTdsStatusEom : 0));
  p.push_back(static_cast<char>(len >> 8));
  p.push_back(static_cast<char>(len & 0xff));
  p.append({0, 0, 1, 0}); // SPID, packet id, window.
  p.append(payload);
  return p;
}

inline std::string tlsRecord(uint8_t content_type, std::string_view payload) {
  std::string r;
  r.push_back(static_cast<char>(content_type));
  r.append({0x03, 0x03});
  r.push_back(static_cast<char>(payload.size() >> 8));
  r.push_back(static_cast<char>(payload.size() & 0xff));
  r.append(payload);
  return r;
}

// PRELOGIN payload with VERSION, ENCRYPTION and (optionally) MARS options.
inline std::string preloginPayload(uint8_t encryption, std::optional<uint8_t> mars = std::nullopt) {
  const size_t options = mars ? 3 : 2;
  const size_t table = options * 5 + 1;
  std::string t, data;
  auto add = [&](uint8_t token, std::string_view value) {
    const size_t offset = table + data.size();
    t.push_back(static_cast<char>(token));
    t.push_back(static_cast<char>(offset >> 8));
    t.push_back(static_cast<char>(offset & 0xff));
    t.push_back(0);
    t.push_back(static_cast<char>(value.size()));
    data.append(value);
  };
  add(0x00, std::string("\x10\x00\x00\x00\x00\x00", 6)); // VERSION
  add(0x01, std::string(1, static_cast<char>(encryption)));
  if (mars) {
    add(0x04, std::string(1, static_cast<char>(*mars)));
  }
  t.push_back(static_cast<char>(0xff));
  return t + data;
}

struct Collect : UnitSink {
  std::vector<Unit> units;
  std::vector<std::string> bytes; // Copies: Unit views die after the callback.
  std::optional<std::string> onUnit(const Unit& u) override {
    units.push_back(u);
    bytes.emplace_back(u.bytes);
    return std::nullopt;
  }
};

inline std::string le16(size_t v) {
  return std::string{static_cast<char>(v & 0xff), static_cast<char>((v >> 8) & 0xff)};
}

inline std::string bVarchar(std::string_view ascii) {
  std::string s(1, static_cast<char>(ascii.size()));
  for (char c : ascii) {
    s.push_back(c);
    s.push_back(0);
  }
  return s;
}

inline std::string envChangePacketSize(std::string_view new_value, std::string_view old_value) {
  const std::string data = std::string(1, 4) + bVarchar(new_value) + bVarchar(old_value);
  return std::string(1, static_cast<char>(0xe3)) + le16(data.size()) + data;
}

inline std::string loginAck() {
  const std::string data(10, 'x');
  return std::string(1, static_cast<char>(0xad)) + le16(data.size()) + data;
}

inline std::string done() { return std::string(1, static_cast<char>(0xfd)) + std::string(12, '\0'); }

} // namespace test
} // namespace MssqlProxy
