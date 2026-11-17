#include "login7.h"

#include <format>
#include <vector>

namespace MssqlProxy {

namespace {

// Fixed part of LOGIN7 up to cbSSPI, as in TDS 7.1; TDS 7.2+ adds
// AtchDBFile, ChangePassword and cbSSPILong (94 bytes).
constexpr size_t kLogin7FixedSize = 86;
constexpr size_t kLogin7FixedSize72 = 94;
// Each string field holds at most 128 characters (MS-TDS 2.2.6.4).
constexpr size_t kMaxFieldChars = 128;

uint16_t le16(std::string_view b, size_t at) {
  return static_cast<uint16_t>(static_cast<uint8_t>(b[at]) |
                               (static_cast<uint8_t>(b[at + 1]) << 8));
}

uint32_t le32(std::string_view b, size_t at) {
  return static_cast<uint32_t>(le16(b, at)) | (static_cast<uint32_t>(le16(b, at + 2)) << 16);
}

void appendUtf8(std::string& out, uint32_t cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  }
}

} // namespace

std::string utf16leToUtf8(std::string_view s) {
  constexpr uint32_t kReplacement = 0xfffd;
  std::string out;
  const size_t units = s.size() / 2;
  for (size_t i = 0; i < units; ++i) {
    const uint32_t u = le16(s, 2 * i);
    if (u >= 0xd800 && u < 0xdc00 && i + 1 < units) {
      const uint32_t low = le16(s, 2 * (i + 1));
      if (low >= 0xdc00 && low < 0xe000) {
        appendUtf8(out, 0x10000 + ((u - 0xd800) << 10) + (low - 0xdc00));
        ++i;
        continue;
      }
    }
    appendUtf8(out, u >= 0xd800 && u < 0xe000 ? kReplacement : u);
  }
  return out;
}

std::optional<Login7> parseLogin7(std::string_view payload, std::string& error) {
  if (payload.size() < kLogin7FixedSize) {
    error = std::format("LOGIN7 of {} bytes is shorter than its fixed part", payload.size());
    return std::nullopt;
  }
  if (payload.size() > kMaxLogin7Size) {
    error = "LOGIN7 too large";
    return std::nullopt;
  }
  const uint32_t length = le32(payload, 0);
  if (length < kLogin7FixedSize || length > payload.size()) {
    error = std::format("LOGIN7 length {} does not fit its {}-byte message", length,
                        payload.size());
    return std::nullopt;
  }
  const std::string_view login = payload.substr(0, length);

  Login7 out;
  out.tds_version = le32(login, 4);
  out.packet_size = le32(login, 8);
  const uint8_t option_flags2 = static_cast<uint8_t>(login[25]);
  const uint8_t option_flags3 = static_cast<uint8_t>(login[27]);
  out.integrated = (option_flags2 & 0x80) != 0;   // fIntSecurity
  out.has_extension = (option_flags3 & 0x10) != 0; // fExtension

  // (offset, character count) pairs at fixed positions; offsets from the start
  // of LOGIN7, characters are UTF-16LE code units.
  auto field = [&](const char* name, size_t at, std::string& into) {
    const size_t offset = le16(login, at);
    const size_t chars = le16(login, at + 2);
    if (chars > kMaxFieldChars) {
      error = std::format("LOGIN7 {} of {} characters", name, chars);
      return false;
    }
    if (offset > login.size() || chars * 2 > login.size() - offset) {
      error = std::format("LOGIN7 {} out of bounds", name);
      return false;
    }
    into = utf16leToUtf8(login.substr(offset, chars * 2));
    return true;
  };
  if (!field("host name", 36, out.host_name) || !field("user name", 40, out.user_name) ||
      !field("app name", 48, out.app_name) || !field("server name", 52, out.server_name) ||
      !field("library name", 60, out.library_name) || !field("language", 64, out.language) ||
      !field("database", 68, out.database)) {
    return std::nullopt;
  }
  // The password (44) is deliberately not read. SSPI data: (offset, bytes);
  // a count of 0xFFFF means the real one is cbSSPILong (TDS 7.2+, at 90).
  const size_t sspi_offset = le16(login, 78);
  size_t sspi_bytes = le16(login, 80);
  if (sspi_bytes == 0xffff && login.size() >= kLogin7FixedSize72) {
    sspi_bytes = le32(login, 90);
  }
  if (sspi_offset > login.size() || sspi_bytes > login.size() - sspi_offset) {
    error = "LOGIN7 SSPI data out of bounds";
    return std::nullopt;
  }
  out.has_sspi = sspi_bytes > 0;
  out.sspi = std::string(login.substr(sspi_offset, sspi_bytes));
  return out;
}

std::optional<std::string> replaceLogin7Sspi(std::string_view payload, std::string_view sspi,
                                             std::string& error) {
  std::optional<Login7> parsed = parseLogin7(payload, error);
  if (!parsed) {
    return std::nullopt;
  }
  std::string login(payload.substr(0, le32(payload, 0)));
  const uint32_t version = parsed->tds_version;
  // TDS 7.2+ has AtchDBFile, ChangePassword and cbSSPILong after cbSSPI.
  const bool tds72 = login.size() >= kLogin7FixedSize72 && version != 0x70000000 &&
                     version != 0x71000000 && version != 0x71000001;
  constexpr size_t kSspiOffset = 78;
  constexpr size_t kSspiBytes = 80;
  constexpr size_t kSspiLong = 90;
  constexpr size_t kExtensionOffset = 56; // ibExtension (ibUnused without fExtension).
  std::vector<size_t> offset_fields = {36, 40, 44, 48, 52, kExtensionOffset, 60, 64, 68};
  if (tds72) {
    offset_fields.insert(offset_fields.end(), {82, 86});
  }

  const size_t start = le16(login, kSspiOffset);
  const size_t old_size = parsed->sspi.size();
  const size_t end = start + old_size;
  if (sspi.size() >= 0xffff && !tds72) {
    error = "SSPI data too large for a TDS 7.1 LOGIN7";
    return std::nullopt;
  }
  const int64_t delta = static_cast<int64_t>(sspi.size()) - static_cast<int64_t>(old_size);

  std::string out = login.substr(0, start);
  out += sspi;
  out += login.substr(end);
  auto put16 = [&](size_t at, size_t v) {
    out[at] = static_cast<char>(v & 0xff);
    out[at + 1] = static_cast<char>((v >> 8) & 0xff);
  };
  auto put32 = [&](size_t at, size_t v) {
    put16(at, v & 0xffff);
    put16(at + 2, (v >> 16) & 0xffff);
  };
  // Moves the offset of size bytes of data that lie at or past the end of the
  // old SSPI data.
  auto moved = [&](size_t offset, size_t size) -> std::optional<size_t> {
    if (old_size > 0 && size > 0 && offset < end && offset + size > start) {
      error = "LOGIN7 data overlaps its SSPI data";
      return std::nullopt;
    }
    return offset >= end ? static_cast<size_t>(static_cast<int64_t>(offset) + delta) : offset;
  };
  for (size_t at : offset_fields) {
    // Lengths count UTF-16 characters, apart from the extension's (bytes).
    const size_t units = le16(login, at + 2);
    const std::optional<size_t> offset =
        moved(le16(login, at), at == kExtensionOffset ? units : 2 * units);
    if (!offset) {
      return std::nullopt;
    }
    if (*offset > 0xffff) {
      error = "LOGIN7 too large after replacing its SSPI data";
      return std::nullopt;
    }
    put16(at, *offset);
  }
  if (parsed->has_extension) {
    // ibExtension points at a DWORD holding the offset of the FeatureExt data.
    const size_t at = le16(out, kExtensionOffset);
    if (le16(login, kExtensionOffset + 2) < 4 || at + 4 > out.size()) {
      error = "LOGIN7 feature extension pointer out of bounds";
      return std::nullopt;
    }
    const std::optional<size_t> feature_ext = moved(le32(out, at), 1);
    if (!feature_ext) {
      return std::nullopt;
    }
    put32(at, *feature_ext);
  }
  if (sspi.size() < 0xffff) {
    put16(kSspiBytes, sspi.size());
    if (tds72) {
      put32(kSspiLong, 0);
    }
  } else {
    put16(kSspiBytes, 0xffff);
    put32(kSspiLong, sspi.size());
  }
  put32(0, out.size());
  if (out.size() > kMaxLogin7Size) {
    error = "LOGIN7 too large after replacing its SSPI data";
    return std::nullopt;
  }
  return out;
}

} // namespace MssqlProxy
