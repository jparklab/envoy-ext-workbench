#pragma once

// NTLM (MS-NLMP) messages as relayed through the proxy: only read, never
// changed (the MIC covers all three messages). The client's identity is in
// plain text in AUTHENTICATE; it is a claim until the server accepts the
// login. No Envoy dependency.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace MssqlProxy {

inline constexpr uint32_t kNtlmNegotiate = 1;
inline constexpr uint32_t kNtlmChallenge = 2;
inline constexpr uint32_t kNtlmAuthenticate = 3;

// The MessageType of an NTLMSSP message, or nullopt when it isn't one.
std::optional<uint32_t> ntlmMessageType(std::string_view message);

struct NtlmAuthenticate {
  std::string domain;      // UTF-8; may be empty (e.g. with a UPN user name).
  std::string user;        // UTF-8.
  std::string workstation; // UTF-8.
  uint32_t flags = 0;      // NegotiateFlags.
  bool unicode = false;    // Strings were UTF-16LE (else OEM, read as ASCII).
  // NtChallengeResponse of 24 bytes: NTLMv1 (with or without extended session
  // security) rather than NTLMv2.
  bool v1 = false;
  // No user and no NT response: an anonymous login.
  bool anonymous = false;
};

// Parses an AUTHENTICATE message; every field is bounds-checked. nullopt and
// error set when malformed.
std::optional<NtlmAuthenticate> parseNtlmAuthenticate(std::string_view message,
                                                      std::string& error);

// The identity an AUTHENTICATE claims: "DOMAIN\user", or the user name alone
// when there is no domain (a UPN such as user@dns.domain arrives this way).
std::string ntlmIdentity(const NtlmAuthenticate& authenticate);

} // namespace MssqlProxy
