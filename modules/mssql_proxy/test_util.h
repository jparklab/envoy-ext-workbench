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

// DER TLV with a single-byte tag.
inline std::string der(uint8_t tag, std::string_view value) {
  std::string out(1, static_cast<char>(tag));
  const size_t n = value.size();
  if (n < 0x80) {
    out.push_back(static_cast<char>(n));
  } else if (n < 0x100) {
    out += {static_cast<char>(0x81), static_cast<char>(n)};
  } else {
    out += {static_cast<char>(0x82), static_cast<char>(n >> 8), static_cast<char>(n & 0xff)};
  }
  return out + std::string(value);
}

// OID contents (DER, without tag and length).
inline const std::string kOidSpnego{"\x2b\x06\x01\x05\x05\x02", 6};
inline const std::string kOidKrb5{"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", 9};
inline const std::string kOidMsKrb5{"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02", 9};
inline const std::string kOidNtlm{"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a", 10};

// A GSS Kerberos token: framing, TOK_ID, then a stand-in for the message.
inline std::string krb5Token(uint16_t tok_id = 0x0100, std::string_view message = "AP-REQ") {
  std::string inner = der(0x06, kOidKrb5);
  inner += {static_cast<char>(tok_id >> 8), static_cast<char>(tok_id & 0xff)};
  inner += message;
  return der(0x60, inner);
}

// An NTLMSSP message of the given type (1 NEGOTIATE, 3 AUTHENTICATE), body
// not filled in.
inline std::string ntlmMessage(uint8_t type) {
  return std::string("NTLMSSP\0", 8) + std::string{static_cast<char>(type), 0, 0, 0} +
         std::string(16, '\0');
}

// SPNEGO NegTokenInit offering mechs, with an optional mechToken.
inline std::string spnegoInit(const std::vector<std::string>& mech_oids,
                              std::optional<std::string> mech_token) {
  std::string oids;
  for (const std::string& oid : mech_oids) {
    oids += der(0x06, oid);
  }
  std::string fields = der(0xa0, der(0x30, oids));
  if (mech_token) {
    fields += der(0xa2, der(0x04, *mech_token));
  }
  return der(0x60, der(0x06, kOidSpnego) + der(0xa0, der(0x30, fields)));
}

// SPNEGO NegTokenResp with a responseToken (as the client sends it later).
inline std::string spnegoResp(std::string_view response_token) {
  return der(0xa1, der(0x30, der(0xa2, der(0x04, response_token))));
}

inline std::string done() { return std::string(1, static_cast<char>(0xfd)) + std::string(12, '\0'); }

// UTF-16LE of an ASCII string.
inline std::string utf16(std::string_view ascii) {
  std::string s;
  for (char c : ascii) {
    s.push_back(c);
    s.push_back(0);
  }
  return s;
}

struct Login7Fields {
  std::string host = "client-host";
  std::string user = "app_user";
  std::string password = "not-a-real-password";
  std::string app = "test-app";
  std::string server = "db.test";
  std::string library = "ODBC";
  std::string language;
  std::string database = "master";
  bool integrated = false;
  std::string sspi;       // SSPI data (the client's first auth token).
  bool sspi_long = false; // Give its length in cbSSPILong (cbSSPI 0xFFFF).
  uint32_t tds_version = 0x74000004;
  uint32_t packet_size = 4096;
};

// A TDS 7.4 LOGIN7 payload (94-byte fixed part, then the strings).
inline std::string login7Payload(const Login7Fields& f = {}) {
  constexpr size_t kFixed = 94;
  std::string fixed(kFixed, '\0');
  std::string data;
  auto put32 = [&](size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
      fixed[at + i] = static_cast<char>((v >> (8 * i)) & 0xff);
    }
  };
  auto put16 = [&](size_t at, size_t v) {
    fixed[at] = static_cast<char>(v & 0xff);
    fixed[at + 1] = static_cast<char>((v >> 8) & 0xff);
  };
  auto str = [&](size_t at, std::string_view ascii) {
    put16(at, kFixed + data.size());
    put16(at + 2, ascii.size());
    data += utf16(ascii);
  };
  put32(4, f.tds_version);
  put32(8, f.packet_size);
  fixed[25] = static_cast<char>(f.integrated ? 0x80 : 0x00);
  str(36, f.host);
  str(40, f.user);
  str(44, f.password);
  str(48, f.app);
  str(52, f.server);
  str(60, f.library);
  str(64, f.language);
  str(68, f.database);
  put16(78, kFixed + data.size());
  if (f.sspi_long) {
    put16(80, 0xffff);
    put32(90, static_cast<uint32_t>(f.sspi.size()));
  } else {
    put16(80, f.sspi.size());
  }
  data += f.sspi;
  put32(0, static_cast<uint32_t>(kFixed + data.size()));
  return fixed + data;
}

} // namespace test
} // namespace MssqlProxy
