#pragma once

// A minimal, bounds-checked ASN.1 DER reader for the authentication messages
// the proxy reads (SPNEGO, Kerberos). Only single-byte tags occur in them;
// indefinite (BER) lengths are rejected. No Envoy dependency.

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>

namespace MssqlProxy {

inline constexpr uint8_t kDerInteger = 0x02;
inline constexpr uint8_t kDerBitString = 0x03;
inline constexpr uint8_t kDerOctetString = 0x04;
inline constexpr uint8_t kDerOid = 0x06;
inline constexpr uint8_t kDerGeneralizedTime = 0x18;
inline constexpr uint8_t kDerGeneralString = 0x1b;
inline constexpr uint8_t kDerSequence = 0x30;

// [n] context-specific, constructed.
constexpr uint8_t derContext(unsigned n) { return static_cast<uint8_t>(0xa0 | n); }
// [APPLICATION n] constructed.
constexpr uint8_t derApplication(unsigned n) { return static_cast<uint8_t>(0x60 | n); }

class Der {
public:
  explicit Der(std::string_view data) : data_(data) {}

  bool empty() const { return pos_ == data_.size(); }
  std::optional<uint8_t> peekTag() const;
  std::string_view rest() const { return data_.substr(pos_); }

  // The contents of the next TLV, which must have this tag.
  std::optional<std::string_view> read(uint8_t tag, std::string& error);
  // The whole next TLV (tag, length and contents), which must have this tag.
  std::optional<std::string_view> readRaw(uint8_t tag, std::string& error);
  // Skips the next TLV, whatever its tag.
  bool skip(std::string& error);

  // [n] EXPLICIT wrappers around a universal type, read in one step.
  std::optional<std::string_view> readExplicit(unsigned n, uint8_t inner, std::string& error);
  std::optional<int64_t> readExplicitInteger(unsigned n, std::string& error);
  std::optional<std::string> readExplicitString(unsigned n, std::string& error);
  // GeneralizedTime "YYYYMMDDHHMMSSZ" as seconds since the epoch.
  std::optional<int64_t> readExplicitTime(unsigned n, std::string& error);
  // Whether the next TLV is [n].
  bool nextIs(unsigned n) const { return peekTag() == derContext(n); }

private:
  // Tag, header length and content length of the next TLV.
  bool header(uint8_t tag, size_t& header_len, size_t& len, std::string& error) const;

  std::string_view data_;
  size_t pos_ = 0;
};

// A DER INTEGER's contents (two's complement, at most 8 bytes).
std::optional<int64_t> derInteger(std::string_view contents, std::string& error);

} // namespace MssqlProxy
