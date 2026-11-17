#include "der.h"

#include <format>

namespace MssqlProxy {

std::optional<uint8_t> Der::peekTag() const {
  return empty() ? std::nullopt : std::optional<uint8_t>(static_cast<uint8_t>(data_[pos_]));
}

bool Der::header(uint8_t tag, size_t& header_len, size_t& len, std::string& error) const {
  if (empty() || static_cast<uint8_t>(data_[pos_]) != tag) {
    error = std::format("expected DER tag 0x{:02x}", tag);
    return false;
  }
  size_t pos = pos_ + 1;
  if (pos >= data_.size()) {
    error = "DER length missing";
    return false;
  }
  len = static_cast<uint8_t>(data_[pos++]);
  if (len & 0x80) {
    const size_t n = len & 0x7f;
    if (n == 0 || n > 4) {
      error = "unsupported DER length"; // Indefinite (BER) or absurdly long.
      return false;
    }
    if (data_.size() - pos < n) {
      error = "DER length truncated";
      return false;
    }
    len = 0;
    for (size_t i = 0; i < n; ++i) {
      len = (len << 8) | static_cast<uint8_t>(data_[pos++]);
    }
  }
  if (len > data_.size() - pos) {
    error = "DER value truncated";
    return false;
  }
  header_len = pos - pos_;
  return true;
}

std::optional<std::string_view> Der::read(uint8_t tag, std::string& error) {
  size_t header_len, len;
  if (!header(tag, header_len, len, error)) {
    return std::nullopt;
  }
  const std::string_view contents = data_.substr(pos_ + header_len, len);
  pos_ += header_len + len;
  return contents;
}

std::optional<std::string_view> Der::readRaw(uint8_t tag, std::string& error) {
  size_t header_len, len;
  if (!header(tag, header_len, len, error)) {
    return std::nullopt;
  }
  const std::string_view whole = data_.substr(pos_, header_len + len);
  pos_ += header_len + len;
  return whole;
}

bool Der::skip(std::string& error) {
  auto tag = peekTag();
  return tag && read(*tag, error).has_value();
}

std::optional<std::string_view> Der::readExplicit(unsigned n, uint8_t inner, std::string& error) {
  auto wrapped = read(derContext(n), error);
  if (!wrapped) {
    return std::nullopt;
  }
  Der der(*wrapped);
  auto contents = der.read(inner, error);
  if (contents && !der.empty()) {
    error = std::format("data after [{}]", n);
    return std::nullopt;
  }
  return contents;
}

std::optional<int64_t> Der::readExplicitInteger(unsigned n, std::string& error) {
  auto contents = readExplicit(n, kDerInteger, error);
  return contents ? derInteger(*contents, error) : std::nullopt;
}

std::optional<std::string> Der::readExplicitString(unsigned n, std::string& error) {
  auto contents = readExplicit(n, kDerGeneralString, error);
  return contents ? std::optional<std::string>(std::string(*contents)) : std::nullopt;
}

std::optional<int64_t> Der::readExplicitTime(unsigned n, std::string& error) {
  auto s = readExplicit(n, kDerGeneralizedTime, error);
  if (!s) {
    return std::nullopt;
  }
  // KerberosTime: "YYYYMMDDHHMMSSZ", no fractions (RFC 4120 5.2.3).
  if (s->size() != 15 || (*s)[14] != 'Z') {
    error = "malformed KerberosTime";
    return std::nullopt;
  }
  int v[6];
  const size_t widths[] = {4, 2, 2, 2, 2, 2};
  size_t at = 0;
  for (int i = 0; i < 6; ++i) {
    v[i] = 0;
    for (size_t k = 0; k < widths[i]; ++k, ++at) {
      const char c = (*s)[at];
      if (c < '0' || c > '9') {
        error = "malformed KerberosTime";
        return std::nullopt;
      }
      v[i] = v[i] * 10 + (c - '0');
    }
  }
  std::tm tm{};
  tm.tm_year = v[0] - 1900;
  tm.tm_mon = v[1] - 1;
  tm.tm_mday = v[2];
  tm.tm_hour = v[3];
  tm.tm_min = v[4];
  tm.tm_sec = v[5];
  return static_cast<int64_t>(timegm(&tm));
}

std::optional<int64_t> derInteger(std::string_view contents, std::string& error) {
  if (contents.empty() || contents.size() > 8) {
    error = "unsupported DER INTEGER size";
    return std::nullopt;
  }
  int64_t value = static_cast<int8_t>(contents[0]); // Sign-extends.
  for (size_t i = 1; i < contents.size(); ++i) {
    value = static_cast<int64_t>(static_cast<uint64_t>(value) << 8) |
            static_cast<uint8_t>(contents[i]);
  }
  return value;
}

} // namespace MssqlProxy
