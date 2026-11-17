#include "ntlm.h"

#include <format>

#include "login7.h"

namespace MssqlProxy {

namespace {

constexpr std::string_view kSignature{"NTLMSSP\0", 8};
// Up to and including NegotiateFlags; Version and MIC follow when present.
constexpr size_t kAuthenticateFixedSize = 64;
constexpr uint32_t kNegotiateUnicode = 0x00000001;
constexpr size_t kNtlmV1ResponseSize = 24;

uint16_t le16(std::string_view b, size_t at) {
  return static_cast<uint16_t>(static_cast<uint8_t>(b[at]) |
                               (static_cast<uint8_t>(b[at + 1]) << 8));
}

uint32_t le32(std::string_view b, size_t at) {
  return static_cast<uint32_t>(le16(b, at)) | (static_cast<uint32_t>(le16(b, at + 2)) << 16);
}

// One (Len, MaxLen, BufferOffset) field at `at`.
std::optional<std::string_view> payloadField(std::string_view message, size_t at,
                                             const char* name, std::string& error) {
  const size_t len = le16(message, at);
  const size_t offset = le32(message, at + 4);
  if (offset > message.size() || len > message.size() - offset) {
    error = std::format("NTLM AUTHENTICATE {} out of bounds", name);
    return std::nullopt;
  }
  return message.substr(offset, len);
}

// OEM strings: the code page isn't known here; ASCII is kept and anything
// else becomes U+FFFD.
std::string oemToUtf8(std::string_view oem) {
  std::string out;
  for (char c : oem) {
    if (static_cast<unsigned char>(c) < 0x80) {
      out.push_back(c);
    } else {
      out += "\xef\xbf\xbd";
    }
  }
  return out;
}

} // namespace

std::optional<uint32_t> ntlmMessageType(std::string_view message) {
  if (message.size() < 12 || !message.starts_with(kSignature)) {
    return std::nullopt;
  }
  return le32(message, 8);
}

std::optional<NtlmAuthenticate> parseNtlmAuthenticate(std::string_view message,
                                                      std::string& error) {
  if (ntlmMessageType(message) != kNtlmAuthenticate) {
    error = "not an NTLM AUTHENTICATE message";
    return std::nullopt;
  }
  if (message.size() < kAuthenticateFixedSize) {
    error = "NTLM AUTHENTICATE truncated";
    return std::nullopt;
  }
  NtlmAuthenticate out;
  out.flags = le32(message, 60);
  out.unicode = (out.flags & kNegotiateUnicode) != 0;

  auto lm = payloadField(message, 12, "LmChallengeResponse", error);
  auto nt = payloadField(message, 20, "NtChallengeResponse", error);
  auto domain = payloadField(message, 28, "DomainName", error);
  auto user = payloadField(message, 36, "UserName", error);
  auto workstation = payloadField(message, 44, "Workstation", error);
  auto session_key = payloadField(message, 52, "EncryptedRandomSessionKey", error);
  if (!lm || !nt || !domain || !user || !workstation || !session_key) {
    return std::nullopt;
  }
  auto text = [&](std::string_view raw, const char* name, std::string& into) {
    if (out.unicode) {
      if (raw.size() % 2 != 0) {
        error = std::format("NTLM AUTHENTICATE {} of odd length in UTF-16", name);
        return false;
      }
      into = utf16leToUtf8(raw);
    } else {
      into = oemToUtf8(raw);
    }
    return true;
  };
  if (!text(*domain, "DomainName", out.domain) || !text(*user, "UserName", out.user) ||
      !text(*workstation, "Workstation", out.workstation)) {
    return std::nullopt;
  }
  out.v1 = nt->size() == kNtlmV1ResponseSize;
  out.anonymous = out.user.empty() && nt->empty();
  return out;
}

std::string ntlmIdentity(const NtlmAuthenticate& a) {
  return a.domain.empty() ? a.user : a.domain + "\\" + a.user;
}

} // namespace MssqlProxy
